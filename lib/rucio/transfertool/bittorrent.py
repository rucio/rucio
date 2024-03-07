# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import logging
from collections.abc import Sequence
from os import path
from typing import TYPE_CHECKING, Any, Mapping, Optional, Type

from rucio.common import types
from rucio.common.config import config_get
from rucio.common.extra import import_extras
from rucio.common.utils import construct_torrent
from rucio.core.did_meta_plugins import get_metadata
from rucio.transfertool.transfertool import Transfertool, TransferToolBuilder, TransferStatusReport
from .bittorrent_driver import BittorrentDriver

if TYPE_CHECKING:
    from rucio.core.request import DirectTransfer
    from rucio.core.rse import RseData

DRIVER_NAME_RSE_ATTRIBUTE = 'bittorrent_driver'
DRIVER_CLASSES_BY_NAME: dict[str, Type[BittorrentDriver]] = {}

EXTRA_MODULES = import_extras(['qbittorrentapi'])

if EXTRA_MODULES['qbittorrentapi']:
    from .bittorrent_driver_qbittorrent import QBittorrentDriver
    DRIVER_CLASSES_BY_NAME[QBittorrentDriver.external_name] = QBittorrentDriver


class BittorrentTransfertool(Transfertool):
    """
    Use bittorrent to perform the peer-to-peer transfer.
    """
    external_name = 'bittorrent'
    supported_schemes = {'magnet'}

    required_rse_attrs = (DRIVER_NAME_RSE_ATTRIBUTE, )

    def __init__(self, external_host: str, logger: types.LoggerFunction = logging.log) -> None:
        super().__init__(external_host=external_host, logger=logger)

        self._drivers_by_rse_id = {}
        self.ca_cert, self.ca_key = None, None

        self.tracker = config_get('transfers', 'bittorrent_tracker_addr', raise_exception=False, default=None)

    @classmethod
    def _pick_management_api_driver_cls(cls: "Type[BittorrentTransfertool]", rse: "RseData") -> Optional[Type[BittorrentDriver]]:
        driver_cls = DRIVER_CLASSES_BY_NAME.get(rse.attributes.get(DRIVER_NAME_RSE_ATTRIBUTE, ''))
        if driver_cls is None:
            return None
        if not all(rse.attributes.get(attribute) is not None for attribute in driver_cls.required_rse_attrs):
            return None
        return driver_cls

    def _driver_for_rse(self, rse: "RseData") -> Optional[BittorrentDriver]:
        driver = self._drivers_by_rse_id.get(rse.id)
        if driver:
            return driver

        driver_cls = self._pick_management_api_driver_cls(rse)
        if not driver_cls:
            return None

        driver = driver_cls.make_driver(rse)
        self._drivers_by_rse_id[rse.id] = driver
        return driver

    @staticmethod
    def _get_torrent_meta(scope: "types.InternalScope", name: str) -> tuple[bytes, bytes, int]:
        meta = get_metadata(scope=scope, name=name, plugin='all')
        pieces_root = base64.b64decode(meta.get('bittorrent_pieces_root', ''))
        pieces_layers = base64.b64decode(meta.get('bittorrent_pieces_layers', ''))
        piece_length = meta.get('bittorrent_piece_length', 0)
        return pieces_root, pieces_layers, piece_length

    @classmethod
    def submission_builder_for_path(
            cls: "Type[BittorrentTransfertool]",
            transfer_path: "list[DirectTransfer]",
            logger: types.LoggerFunction = logging.log
    ) -> "tuple[list[DirectTransfer], Optional[TransferToolBuilder]]":
        hop = transfer_path[0]
        if hop.rws.byte_count == 0:
            logger(logging.INFO, f"Bittorrent cannot transfer fully empty torrents. Skipping {hop}")
            return [], None

        if not cls.can_perform_transfer(hop.src.rse, hop.dst.rse):
            logger(logging.INFO, f"The required RSE attributes are not set. Skipping {hop}")
            return [], None

        for rse in [hop.src.rse, hop.dst.rse]:
            driver_cls = cls._pick_management_api_driver_cls(rse)
            if not driver_cls:
                logger(logging.INFO, f"The rse '{rse}' is not configured correctly for bittorrent")
                return [], None

        pieces_root, _pieces_layers, piece_length = cls._get_torrent_meta(hop.rws.scope, hop.rws.name)
        if not pieces_root or not piece_length:
            logger(logging.INFO, "The required bittorrent metadata not set on the DID")
            return [], None

        return [hop], TransferToolBuilder(cls, external_host='Bittorrent Transfertool')

    def group_into_submit_jobs(self, transfer_paths: "Sequence[list[DirectTransfer]]") -> list[dict[str, Any]]:
        return [{'transfers': transfer_path, 'job_params': {}} for transfer_path in transfer_paths]

    @staticmethod
    def _connect_directly(torrent_id: str, peers_drivers: Sequence[BittorrentDriver]) -> None:
        peer_addr = []
        for i, driver in enumerate(peers_drivers):
            peer_addr.append(driver.listen_addr())

        for driver in peers_drivers:
            driver.add_peers(torrent_id=torrent_id, peers=peer_addr)

    def submit(self, transfers: "Sequence[DirectTransfer]", job_params: dict[str, str], timeout: Optional[int] = None) -> str:
        [transfer] = transfers
        rws = transfer.rws

        tracker = transfer.dst.rse.attributes.get('bittorrent_tracker_addr', self.tracker)

        src_drivers = {}
        for source in transfer.sources:
            driver = self._driver_for_rse(source.rse)
            if driver:
                src_drivers[source] = driver

        dst_driver = self._driver_for_rse(transfer.dst.rse)

        if not dst_driver or not src_drivers:
            raise Exception('Cannot initialize bittorrent drivers to submit transfers')

        pieces_root, pieces_layers, piece_length = self._get_torrent_meta(rws.scope, rws.name)
        torrent_id, torrent = construct_torrent(
            scope=str(rws.scope),
            name=rws.name,
            length=rws.byte_count,
            piece_length=piece_length,
            pieces_root=pieces_root,
            pieces_layers=pieces_layers,
            trackers=[tracker] if tracker else None,
        )

        for source, driver in src_drivers.items():
            source_protocol = transfer.source_protocol(source)
            [lfn] = source_protocol.parse_pfns([transfer.source_url(source)]).values()
            driver.add_torrent(
                file_name=rws.name,
                file_content=torrent,
                download_location=lfn['prefix'] + path.dirname(lfn['path']),
                seed_mode=True,
            )

        dest_protocol = transfer.dest_protocol()
        [lfn] = dest_protocol.parse_pfns([transfer.dest_url]).values()
        dst_driver.add_torrent(
            file_name=rws.name,
            file_content=torrent,
            download_location=lfn['prefix'] + lfn['path'],
        )

        self._connect_directly(torrent_id, [dst_driver] + list(src_drivers.values()))
        return torrent_id

    def bulk_query(self, requests_by_eid, timeout: Optional[int] = None) -> Mapping[str, Mapping[str, TransferStatusReport]]:
        response = {}
        for transfer_id, requests in requests_by_eid.items():
            for request_id, request in requests.items():
                driver = self._driver_for_rse(request['dst_rse'])
                if not driver:
                    self.logger(f'Cannot instantiate BitTorrent driver for {request["dest_rse"]}')
                    continue
                response.setdefault(transfer_id, {})[request_id] = driver.get_status(request_id=request_id, torrent_id=transfer_id)
        return response

    def query(self, transfer_ids: Sequence[str], details: bool = False, timeout: Optional[int] = None) -> None:
        pass

    def cancel(self, transfer_ids: Sequence[str], timeout: Optional[int] = None) -> None:
        pass

    def update_priority(self, transfer_id: str, priority: int, timeout: Optional[int] = None) -> None:
        pass
