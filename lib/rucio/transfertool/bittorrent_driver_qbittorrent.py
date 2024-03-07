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

import logging
from collections.abc import Sequence
from typing import TYPE_CHECKING, cast, Optional
from urllib.parse import urlparse

import qbittorrentapi

from rucio.common import types
from rucio.common.config import get_rse_credentials
from rucio.common.utils import resolve_ip
from rucio.core.oidc import request_token
from rucio.db.sqla.constants import RequestState
from rucio.transfertool.transfertool import TransferStatusReport
from .bittorrent_driver import BittorrentDriver

if TYPE_CHECKING:
    from typing import Type
    from sqlalchemy.orm import Session
    from rucio.core.rse import RseData


class QBittorrentTransferStatusReport(TransferStatusReport):

    supported_db_fields = [
        'state',
        'external_id',
    ]

    def __init__(self, request_id: str, external_id: str, qbittorrent_response: Optional[qbittorrentapi.TorrentDictionary]) -> None:
        super().__init__(request_id)

        if qbittorrent_response and qbittorrent_response.state_enum.is_complete == 1:
            new_state = RequestState.DONE
        else:
            new_state = RequestState.SUBMITTED

        self.state = new_state
        self.external_id = None
        if new_state in [RequestState.FAILED, RequestState.DONE]:
            self.external_id = external_id

    def initialize(self, session: "Session", logger: types.LoggerFunction = logging.log) -> None:
        pass

    def get_monitor_msg_fields(self, session: "Session", logger: types.LoggerFunction = logging.log) -> dict[str, str]:
        return {'protocol': 'qbittorrent'}


class QBittorrentDriver(BittorrentDriver):

    external_name = 'qbittorrent'
    required_rse_attrs = ('qbittorrent_management_address', )

    @classmethod
    def make_driver(cls: "Type[QBittorrentDriver]", rse: "RseData", logger: types.LoggerFunction = logging.log) -> "Optional[BittorrentDriver]":

        address = rse.attributes.get('qbittorrent_management_address')
        if not address:
            return None

        url = urlparse(address)
        token = None
        if url.scheme.lower() == 'https':
            token = request_token(audience=url.hostname, scope='qbittorrent_admin')
        else:
            logging.debug(f'{cls.external_name} will not try token authentication. Requires HTTPS.')

        rse_cred = get_rse_credentials().get(rse.id, {})
        username = rse_cred.get('qbittorrent_username')
        password = rse_cred.get('qbittorrent_password')

        if not (token or (username and password)):
            return None

        return cls(
            address=address,
            username=username,
            password=password,
            token=token,
            logger=logger,
        )

    def __init__(self, address: str, username: str, password: str, token: Optional[str] = None, logger: types.LoggerFunction = logging.log) -> None:
        extra_headers = None
        if token:
            extra_headers = {'Authorization': 'Bearer ' + token}

        self.client = qbittorrentapi.Client(
            host=address,
            username=username,
            password=password,
            EXTRA_HEADERS=extra_headers,
            FORCE_SCHEME_FROM_HOST=True,
        )
        self.logger = logger

    def listen_addr(self) -> tuple[str, int]:
        preferences = self.client.app_preferences()
        port = cast(int, preferences['listen_port'])
        ip = resolve_ip(urlparse(self.client.host).hostname or self.client.host)
        return ip, port

    def add_torrent(self, file_name: str, file_content: bytes, download_location: str, seed_mode: bool = False) -> None:
        self.client.torrents_add(
            rename=file_name,
            torrent_files=file_content,
            save_path=download_location,
            is_skip_checking=seed_mode,
            is_sequential_download=True,
        )

    def add_peers(self, torrent_id: str, peers: Sequence[tuple[str, int]]) -> None:
        self.client.torrents_add_peers(torrent_hashes=[torrent_id], peers=[f'{ip}:{port}' for ip, port in peers])

    def get_status(self, request_id: str, torrent_id: str) -> TransferStatusReport:
        info = self.client.torrents_info(torrent_hashes=[torrent_id])
        return QBittorrentTransferStatusReport(request_id, external_id=torrent_id, qbittorrent_response=info[0] if info else None)
