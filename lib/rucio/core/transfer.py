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

import datetime
import logging
import operator
import re
import sys
import time
import traceback
from collections import defaultdict
from typing import TYPE_CHECKING, cast

from dogpile.cache import make_region
from dogpile.cache.api import NoValue
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from rucio.common import constants
from rucio.common.config import config_get, config_get_list
from rucio.common.constants import SUPPORTED_PROTOCOLS
from rucio.common.exception import (InvalidRSEExpression,
                                    RequestNotFound, RSEProtocolNotSupported,
                                    RucioException, UnsupportedOperation)
from rucio.common.utils import construct_surl
from rucio.core import did, message as message_core, request as request_core
from rucio.core.account import list_accounts
from rucio.core.monitor import MetricManager
from rucio.core.request import transition_request_state, RequestWithSources, RequestSource, TransferDestination, DirectTransfer
from rucio.core.rse import RseData
from rucio.core.rse_expression_parser import parse_expression
from rucio.db.sqla import models
from rucio.db.sqla.constants import DIDType, RequestState, RequestType, TransferLimitDirection
from rucio.db.sqla.session import read_session, transactional_session, stream_session
from rucio.rse import rsemanager as rsemgr
from rucio.transfertool.transfertool import TransferStatusReport, Transfertool
from rucio.transfertool.bittorrent import BittorrentTransfertool
from rucio.transfertool.fts3 import FTS3Transfertool
from rucio.transfertool.globus import GlobusTransferTool
from rucio.transfertool.mock import MockTransfertool

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Iterable, Mapping, Sequence
    from typing import Any, Optional, Type
    from sqlalchemy.orm import Session
    from rucio.common.types import InternalAccount
    from rucio.core.topology import Topology
    from rucio.rse.protocols.protocol import RSEProtocol

    LoggerFunction = Callable[..., Any]

"""
The core transfer.py is specifically for handling transfer-requests, thus requests
where the external_id is already known.
Requests accessed by request_id  are covered in the core request.py
"""

REGION_ACCOUNTS = make_region().configure('dogpile.cache.memory', expiration_time=600)
METRICS = MetricManager(module=__name__)

WEBDAV_TRANSFER_MODE = config_get('conveyor', 'webdav_transfer_mode', False, None)

DEFAULT_MULTIHOP_TOMBSTONE_DELAY = int(datetime.timedelta(hours=2).total_seconds())

TRANSFERTOOL_CLASSES_BY_NAME: "dict[str, Type[Transfertool]]" = {
    FTS3Transfertool.external_name: FTS3Transfertool,
    GlobusTransferTool.external_name: GlobusTransferTool,
    MockTransfertool.external_name: MockTransfertool,
    BittorrentTransfertool.external_name: BittorrentTransfertool,
}


class ProtocolFactory:
    """
    Creates and caches protocol objects. Allowing to reuse them.
    """
    def __init__(self):
        self.protocols = {}

    def protocol(self, rse: RseData, scheme: "Optional[str]", operation: str):
        protocol_key = '%s_%s_%s' % (operation, rse.id, scheme)
        protocol = self.protocols.get(protocol_key)
        if not protocol:
            protocol = rsemgr.create_protocol(rse.info, operation, scheme)
            self.protocols[protocol_key] = protocol
        return protocol


class DirectTransferImplementation(DirectTransfer):
    """
    The configuration for a direct (non-multi-hop) transfer. It can be a multi-source transfer.

    The class wraps the legacy dict-based transfer definition to maintain compatibility with existing code
    during the migration.
    """
    def __init__(self, source: RequestSource, destination: TransferDestination, rws: RequestWithSources,
                 protocol_factory: ProtocolFactory, operation_src: str, operation_dest: str):
        super().__init__(sources=[source], rws=rws)
        self.destination = destination

        self.protocol_factory = protocol_factory
        self.operation_src = operation_src
        self.operation_dest = operation_dest

        self._dest_url = None
        self._source_urls = {}

    def __str__(self):
        return '{sources}--{request_id}->{destination}'.format(
            sources=','.join([str(s.rse) for s in self.sources]),
            request_id=self.rws.request_id or '',
            destination=self.dst.rse
        )

    @property
    def src(self) -> RequestSource:
        return self.sources[0]

    @property
    def dst(self) -> TransferDestination:
        return self.destination

    @property
    def dest_url(self) -> str:
        if not self._dest_url:
            self._dest_url = self._generate_dest_url(self.dst, self.rws, self.protocol_factory, self.operation_dest)
        return self._dest_url

    def source_url(self, source: RequestSource) -> str:
        url = self._source_urls.get(source.rse)
        if not url:
            self._source_urls[source.rse] = url = self._generate_source_url(
                source,
                self.dst,
                rws=self.rws,
                protocol_factory=self.protocol_factory,
                operation=self.operation_src
            )
        return url

    def dest_protocol(self) -> "RSEProtocol":
        return self.protocol_factory.protocol(self.dst.rse, self.dst.scheme, self.operation_dest)

    def source_protocol(self, source: RequestSource) -> "RSEProtocol":
        return self.protocol_factory.protocol(source.rse, source.scheme, self.operation_src)

    @staticmethod
    def __rewrite_source_url(source_url, source_sign_url, dest_sign_url, source_scheme):
        """
        Parametrize source url for some special cases of source and destination schemes
        """
        if dest_sign_url == 'gcs':
            if source_scheme in ['davs', 'https']:
                source_url += '?copy_mode=push'
        elif dest_sign_url == 's3':
            if source_scheme in ['davs', 'https']:
                source_url += '?copy_mode=push'
        elif WEBDAV_TRANSFER_MODE:
            if source_scheme in ['davs', 'https']:
                source_url += '?copy_mode=%s' % WEBDAV_TRANSFER_MODE

        source_sign_url_map = {'gcs': 'gclouds', 's3': 's3s'}
        if source_sign_url in source_sign_url_map:
            if source_url[:7] == 'davs://':
                source_url = source_sign_url_map[source_sign_url] + source_url[4:]
            if source_url[:8] == 'https://':
                source_url = source_sign_url_map[source_sign_url] + source_url[5:]

        if source_url[:12] == 'srm+https://':
            source_url = 'srm' + source_url[9:]
        return source_url

    @staticmethod
    def __rewrite_dest_url(dest_url, dest_sign_url):
        """
        Parametrize destination url for some special cases of destination schemes
        """
        if dest_sign_url == 'gcs':
            dest_url = re.sub('davs', 'gclouds', dest_url)
            dest_url = re.sub('https', 'gclouds', dest_url)
        elif dest_sign_url == 's3':
            dest_url = re.sub('davs', 's3s', dest_url)
            dest_url = re.sub('https', 's3s', dest_url)

        if dest_url[:12] == 'srm+https://':
            dest_url = 'srm' + dest_url[9:]
        return dest_url

    @classmethod
    def _generate_source_url(cls, src: RequestSource, dst: TransferDestination, rws: RequestWithSources, protocol_factory: ProtocolFactory, operation: str):
        """
        Generate the source url which will be used as origin to copy the file from request rws towards the given dst endpoint
        """
        # Get source protocol
        protocol = protocol_factory.protocol(src.rse, src.scheme, operation)

        # Compute the source URL
        source_sign_url = src.rse.attributes.get('sign_url', None)
        dest_sign_url = dst.rse.attributes.get('sign_url', None)
        source_url = list(protocol.lfns2pfns(lfns={'scope': rws.scope.external, 'name': rws.name, 'path': src.file_path}).values())[0]
        source_url = cls.__rewrite_source_url(source_url, source_sign_url=source_sign_url, dest_sign_url=dest_sign_url, source_scheme=src.scheme)
        return source_url

    @classmethod
    def _generate_dest_url(cls, dst: TransferDestination, rws: RequestWithSources, protocol_factory: ProtocolFactory, operation: str):
        """
        Generate the destination url for copying the file of request rws
        """
        # Get destination protocol
        protocol = protocol_factory.protocol(dst.rse, dst.scheme, operation)

        if dst.rse.info['deterministic']:
            dest_url = list(protocol.lfns2pfns(lfns={'scope': rws.scope.external, 'name': rws.name}).values())[0]
        else:
            # compute dest url in case of non deterministic
            # naming convention, etc.
            dsn = get_dsn(rws.scope, rws.name, rws.attributes.get('dsn', None))
            # DQ2 path always starts with /, but prefix might not end with /
            naming_convention = dst.rse.attributes.get('naming_convention', None)
            dest_path = construct_surl(dsn, rws.scope.external, rws.name, naming_convention)
            if dst.rse.is_tape():
                if rws.retry_count or rws.activity == 'Recovery':
                    dest_path = '%s_%i' % (dest_path, int(time.time()))

            dest_url = list(protocol.lfns2pfns(lfns={'scope': rws.scope.external, 'name': rws.name, 'path': dest_path}).values())[0]

        dest_sign_url = dst.rse.attributes.get('sign_url', None)
        dest_url = cls.__rewrite_dest_url(dest_url, dest_sign_url=dest_sign_url)
        return dest_url


class StageinTransferImplementation(DirectTransferImplementation):
    """
    A definition of a transfer which triggers a stagein operation.
        - The source and destination url are identical
        - must be from TAPE to non-TAPE RSE
        - can only have one source
    """
    def __init__(
            self,
            source: RequestSource,
            destination: TransferDestination,
            rws: RequestWithSources,
            protocol_factory: ProtocolFactory,
            operation_src: str,
            operation_dest: str
    ):
        if not source.rse.is_tape() or destination.rse.is_tape():
            # allow staging_required QoS RSE to be TAPE to TAPE for pin
            if not destination.rse.attributes.get('staging_required', None):
                raise RucioException("Stageing request {} must be from TAPE to DISK rse. Got {} and {}.".format(rws, source, destination))
        super().__init__(source, destination, rws, protocol_factory, operation_src, operation_dest)

    @property
    def dest_url(self) -> str:
        if not self._dest_url:
            self._dest_url = self.src.url if self.src.url else self._generate_source_url(self.src,
                                                                                         self.dst,
                                                                                         rws=self.rws,
                                                                                         protocol_factory=self.protocol_factory,
                                                                                         operation=self.operation_dest)
        return self._dest_url

    def source_url(self, source: RequestSource) -> str:
        # Source and dest url is the same for stagein requests
        return self.dest_url


def transfer_path_str(transfer_path: "list[DirectTransfer]") -> str:
    """
    an implementation of __str__ for a transfer path, which is a list of direct transfers, so not really an object
    """
    if not transfer_path:
        return 'empty transfer path'

    multi_tt = False
    if len({hop.rws.transfertool for hop in transfer_path if hop.rws.transfertool}) > 1:
        # The path relies on more than one transfertool
        multi_tt = True

    if len(transfer_path) == 1:
        return str(transfer_path[0])

    path_str = str(transfer_path[0].src.rse)
    for hop in transfer_path:
        path_str += '--{request_id}{transfertool}->{destination}'.format(
            request_id=hop.rws.request_id or '',
            transfertool=':{}'.format(hop.rws.transfertool) if multi_tt else '',
            destination=hop.dst.rse,
        )
    return path_str


@transactional_session
def mark_submitting(
        transfer: "DirectTransfer",
        external_host: str,
        *,
        logger: "Callable",
        session: "Session",
):
    """
    Mark a transfer as submitting

    :param transfer:   A transfer object
    :param session:    Database session to use.
    """

    log_str = 'PREPARING REQUEST %s DID %s:%s TO SUBMITTING STATE PREVIOUS %s FROM %s TO %s USING %s ' % (transfer.rws.request_id,
                                                                                                          transfer.rws.scope,
                                                                                                          transfer.rws.name,
                                                                                                          transfer.rws.previous_attempt_id,
                                                                                                          [transfer.source_url(s) for s in transfer.sources],
                                                                                                          transfer.dest_url,
                                                                                                          external_host)
    logger(logging.DEBUG, "%s", log_str)

    stmt = update(
        models.Request
    ).where(
        models.Request.id == transfer.rws.request_id,
        models.Request.state == RequestState.QUEUED
    ).execution_options(
        synchronize_session=False
    ).values(
        {
            'state': RequestState.SUBMITTING,
            'external_id': None,
            'external_host': external_host,
            'dest_url': transfer.dest_url,
            'submitted_at': datetime.datetime.utcnow(),
        }
    )
    rowcount = session.execute(stmt).rowcount

    if rowcount == 0:
        raise RequestNotFound("Failed to prepare transfer: request %s does not exist or is not in queued state" % transfer.rws)


@transactional_session
def ensure_db_sources(
        transfer_path: "list[DirectTransfer]",
        *,
        logger: "Callable",
        session: "Session",
):
    """
    Ensure the needed DB source objects exist
    """

    desired_sources = []
    for transfer in transfer_path:

        for source in transfer.sources:
            common_source_attrs = {
                "scope": transfer.rws.scope,
                "name": transfer.rws.name,
                "rse_id": source.rse.id,
                "dest_rse_id": transfer.dst.rse.id,
                "ranking": source.ranking,
                "bytes": transfer.rws.byte_count,
                "url": transfer.source_url(source),
                "is_using": True,
            }

            desired_sources.append({'request_id': transfer.rws.request_id, **common_source_attrs})
            if len(transfer_path) > 1 and transfer is not transfer_path[-1]:
                # For multihop transfers, each hop's source is also an initial transfer's source.
                desired_sources.append({'request_id': transfer_path[-1].rws.request_id, **common_source_attrs})

    for source in desired_sources:
        stmt = update(
            models.Source
        ).where(
            models.Source.request_id == source['request_id'],
            models.Source.rse_id == source['rse_id']
        ).execution_options(
            synchronize_session=False
        ).values(
            is_using=True
        )
        src_rowcount = session.execute(stmt).rowcount
        if src_rowcount == 0:
            models.Source(**source).save(session=session, flush=False)


@transactional_session
def set_transfers_state(
        transfers,
        state: "RequestState",
        submitted_at: datetime.datetime,
        external_host: str,
        external_id: str,
        transfertool: str,
        *,
        session: "Session",
        logger
):
    """
    Update the transfer info of a request.
    :param transfers:  Dictionary containing request transfer info.
    :param session:    Database session to use.
    """

    logger(logging.INFO, 'Setting state(%s), transfertool(%s), external_host(%s) and eid(%s) for transfers: %s',
           state.name, transfertool, external_host, external_id, ', '.join(t.rws.request_id for t in transfers))
    try:
        for transfer in transfers:
            rws = transfer.rws
            logger(logging.DEBUG, 'COPYING REQUEST %s DID %s:%s USING %s with state(%s) with eid(%s)' % (rws.request_id, rws.scope, rws.name, external_host, state, external_id))
            stmt = update(
                models.Request
            ).where(
                models.Request.id == transfer.rws.request_id,
                models.Request.state == RequestState.SUBMITTING
            ).execution_options(
                synchronize_session=False
            ).values(
                {
                    models.Request.state: state,
                    models.Request.external_id: external_id,
                    models.Request.external_host: external_host,
                    models.Request.source_rse_id: transfer.src.rse.id,
                    models.Request.submitted_at: submitted_at,
                    models.Request.transfertool: transfertool,
                }
            )
            rowcount = session.execute(stmt).rowcount

            if rowcount == 0:
                raise RucioException("%s: failed to set transfer state: request doesn't exist or is not in SUBMITTING state" % rws)

            stmt = select(
                models.DataIdentifier.datatype
            ).where(
                models.DataIdentifier.scope == rws.scope,
                models.DataIdentifier.name == rws.name,
            )
            datatype = session.execute(stmt).scalar_one_or_none()

            msg = {'request-id': rws.request_id,
                   'request-type': rws.request_type,
                   'scope': rws.scope.external,
                   'name': rws.name,
                   'dataset': None,
                   'datasetScope': None,
                   'src-rse-id': transfer.src.rse.id,
                   'src-rse': transfer.src.rse.name,
                   'dst-rse-id': transfer.dst.rse.id,
                   'dst-rse': transfer.dst.rse.name,
                   'state': state,
                   'activity': rws.activity,
                   'file-size': rws.byte_count,
                   'bytes': rws.byte_count,
                   'checksum-md5': rws.md5,
                   'checksum-adler': rws.adler32,
                   'external-id': external_id,
                   'external-host': external_host,
                   'queued_at': str(submitted_at),
                   'datatype': datatype}
            if rws.scope.vo != 'def':
                msg['vo'] = rws.scope.vo

            ds_scope = transfer.rws.attributes.get('ds_scope')
            if ds_scope:
                msg['datasetScope'] = ds_scope
            ds_name = transfer.rws.attributes.get('ds_name')
            if ds_name:
                msg['dataset'] = ds_name

            if msg['request-type']:
                transfer_status = '%s-%s' % (msg['request-type'].name, msg['state'].name)
            else:
                transfer_status = 'transfer-%s' % msg['state']
            transfer_status = transfer_status.lower()

            message_core.add_message(transfer_status, msg, session=session)

    except IntegrityError as error:
        raise RucioException(error.args)

    logger(logging.DEBUG, 'Finished to register transfer state for %s' % external_id)


@transactional_session
def update_transfer_state(
        tt_status_report: TransferStatusReport,
        stats_manager: request_core.TransferStatsManager,
        *,
        session: "Session",
        logger=logging.log
):
    """
    Used by poller and consumer to update the internal state of requests,
    after the response by the external transfertool.

    :param tt_status_report:      The transfertool status update, retrieved via request.query_request().
    :param session:               The database session to use.
    :param logger:                Optional decorated logger that can be passed from the calling daemons or servers.
    :returns:                     The number of updated requests
    """

    request_id = tt_status_report.request_id
    nb_updated = 0
    try:
        fields_to_update = tt_status_report.get_db_fields_to_update(session=session, logger=logger)
        if not fields_to_update:
            request_core.update_request(request_id, raise_on_missing=True, session=session)
            return False
        else:
            logger(logging.INFO, 'UPDATING REQUEST %s FOR %s with changes: %s' % (str(request_id), tt_status_report, fields_to_update))

            request = request_core.get_request(request_id, session=session)
            updated = transition_request_state(request_id, request=request, session=session, **fields_to_update)

            if not updated:
                return nb_updated
            nb_updated += 1

            if tt_status_report.state == RequestState.FAILED:
                if request_core.is_intermediate_hop(request):
                    nb_updated += request_core.handle_failed_intermediate_hop(request, session=session)

            if tt_status_report.state:
                stats_manager.observe(
                    src_rse_id=request['source_rse_id'],
                    dst_rse_id=request['dest_rse_id'],
                    activity=request['activity'],
                    state=tt_status_report.state,
                    file_size=request['bytes'],
                    submitted_at=request.get('submitted_at', None),
                    started_at=fields_to_update.get('started_at', None),
                    transferred_at=fields_to_update.get('transferred_at', None),
                    session=session,
                )
            request_core.add_monitor_message(
                new_state=tt_status_report.state,
                request=request,
                additional_fields=tt_status_report.get_monitor_msg_fields(session=session, logger=logger),
                session=session
            )
            return nb_updated
    except UnsupportedOperation as error:
        logger(logging.WARNING, "Request %s doesn't exist - Error: %s" % (request_id, str(error).replace('\n', '')))
        return 0
    except Exception:
        logger(logging.CRITICAL, "Exception", exc_info=True)


@transactional_session
def mark_transfer_lost(request, *, session: "Session", logger=logging.log):
    new_state = RequestState.LOST
    reason = "The FTS job lost"

    err_msg = request_core.get_transfer_error(new_state, reason)
    transition_request_state(request['id'], state=new_state, external_id=request['external_id'], err_msg=err_msg, session=session, logger=logger)

    request_core.add_monitor_message(new_state=new_state, request=request, additional_fields={'reason': reason}, session=session)


@METRICS.count_it
@transactional_session
def touch_transfer(external_host, transfer_id, *, session: "Session"):
    """
    Update the timestamp of requests in a transfer. Fails silently if the transfer_id does not exist.
    :param request_host:   Name of the external host.
    :param transfer_id:    External transfer job id as a string.
    :param session:        Database session to use.
    """
    try:
        # don't touch it if it's already touched in 30 seconds
        stmt = update(
            models.Request
        ).prefix_with(
            "/*+ INDEX(REQUESTS REQUESTS_EXTERNALID_UQ) */", dialect='oracle'
        ).where(
            models.Request.external_id == transfer_id,
            models.Request.state == RequestState.SUBMITTED,
            models.Request.updated_at < datetime.datetime.utcnow() - datetime.timedelta(seconds=30)
        ).execution_options(
            synchronize_session=False
        ).values(
            updated_at=datetime.datetime.utcnow()
        )
        session.execute(stmt)
    except IntegrityError as error:
        raise RucioException(error.args)


def _create_transfer_definitions(
        topology: "Topology",
        protocol_factory: ProtocolFactory,
        rws: RequestWithSources,
        sources: "Iterable[RequestSource]",
        max_sources: int,
        multi_source_sources: "Iterable[RequestSource]",
        limit_dest_schemes: list[str],
        operation_src: str,
        operation_dest: str,
        domain: str,
        *,
        session: "Session",
) -> "dict[RseData, list[DirectTransfer]]":
    """
    Find the all paths from sources towards the destination of the given transfer request.
    Create the transfer definitions for each point-to-point transfer (multi-source, when possible)
    """
    shortest_paths = topology.search_shortest_paths(src_nodes=[s.rse for s in sources], dst_node=rws.dest_rse,
                                                    operation_src=operation_src, operation_dest=operation_dest,
                                                    domain=domain, limit_dest_schemes=limit_dest_schemes, session=session)

    transfers_by_source = {}
    sources_by_rse = {s.rse: s for s in sources}
    paths_by_source = {sources_by_rse[rse]: path for rse, path in shortest_paths.items()}
    for source, list_hops in paths_by_source.items():
        transfer_path = []
        for hop in list_hops:
            hop_src_rse = hop['source_rse']
            hop_dst_rse = hop['dest_rse']
            src = RequestSource(
                rse=hop_src_rse,
                file_path=source.file_path if hop_src_rse == source.rse else None,
                ranking=source.ranking if hop_src_rse == source.rse else 0,
                distance=hop['cumulated_distance'] if hop_src_rse == source.rse else hop['hop_distance'],
                scheme=hop['source_scheme'],
            )
            dst = TransferDestination(
                rse=hop_dst_rse,
                scheme=hop['dest_scheme'],
            )
            hop_definition = DirectTransferImplementation(
                source=src,
                destination=dst,
                operation_src=operation_src,
                operation_dest=operation_dest,
                # keep the current rws for last hop; create a new one for other hops
                rws=rws if hop_dst_rse == rws.dest_rse else RequestWithSources(
                    id_=None,
                    request_type=rws.request_type,
                    rule_id=None,
                    scope=rws.scope,
                    name=rws.name,
                    md5=rws.md5,
                    adler32=rws.adler32,
                    byte_count=rws.byte_count,
                    activity=rws.activity,
                    attributes={
                        'activity': rws.activity,
                        'source_replica_expression': None,
                        'lifetime': None,
                        'ds_scope': None,
                        'ds_name': None,
                        'bytes': rws.byte_count,
                        'md5': rws.md5,
                        'adler32': rws.adler32,
                        'priority': None,
                        'allow_tape_source': True
                    },
                    previous_attempt_id=None,
                    dest_rse=hop_dst_rse,
                    account=rws.account,
                    retry_count=0,
                    priority=rws.priority,
                    transfertool=rws.transfertool,
                ),
                protocol_factory=protocol_factory,
            )

            transfer_path.append(hop_definition)
        transfers_by_source[source.rse] = transfer_path

    # create multi-source transfers: add additional sources if possible
    for transfer_path in transfers_by_source.values():
        if len(transfer_path) == 1 and not transfer_path[0].src.rse.is_tape():
            # Multiple single-hop DISK rses can be used together in "multi-source" transfers
            #
            # Try adding additional single-hop DISK rses sources to the transfer
            main_source_schemes = __add_compatible_schemes(schemes=[transfer_path[0].dst.scheme], allowed_schemes=SUPPORTED_PROTOCOLS)
            added_sources = 0
            for source in sorted(multi_source_sources, key=lambda s: (-s.ranking, s.distance)):
                if added_sources >= max_sources:
                    break

                edge = topology.edge(source.rse, transfer_path[0].dst.rse)
                if not edge:
                    # There is no direct connection between this source and the destination
                    continue

                if source.rse == transfer_path[0].src.rse:
                    # This is the main source. Don't add a duplicate.
                    continue

                if source.rse.is_tape():
                    continue

                try:
                    matching_scheme = rsemgr.find_matching_scheme(
                        rse_settings_src=source.rse.info,
                        rse_settings_dest=transfer_path[0].dst.rse.info,
                        operation_src=operation_src,
                        operation_dest=operation_dest,
                        domain=domain,
                        scheme=main_source_schemes)
                except RSEProtocolNotSupported:
                    continue

                transfer_path[0].sources.append(
                    RequestSource(
                        rse=source.rse,
                        file_path=source.file_path,
                        ranking=source.ranking,
                        distance=edge.cost,
                        scheme=matching_scheme[1],
                    )
                )
                added_sources += 1
    return transfers_by_source


def _create_stagein_definitions(
        rws: RequestWithSources,
        sources: "Iterable[RequestSource]",
        limit_dest_schemes: list[str],
        operation_src: str,
        operation_dest: str,
        protocol_factory: ProtocolFactory,
) -> "dict[RseData, list[DirectTransfer]]":
    """
    for each source, create a single-hop transfer path with a one stageing definition inside
    """
    transfers_by_source = {
        source.rse: [
            cast(DirectTransfer, StageinTransferImplementation(
                source=RequestSource(
                    rse=source.rse,
                    file_path=source.file_path,
                    url=source.url,
                    scheme=limit_dest_schemes,
                ),
                destination=TransferDestination(
                    rse=rws.dest_rse,
                    scheme=limit_dest_schemes,
                ),
                operation_src=operation_src,
                operation_dest=operation_dest,
                rws=rws,
                protocol_factory=protocol_factory,
            ))

        ]
        for source in sources
    }
    return transfers_by_source


def get_dsn(scope, name, dsn):
    if dsn:
        return dsn
    # select a containing dataset
    for parent in did.list_parent_dids(scope, name):
        if parent['type'] == DIDType.DATASET:
            return parent['name']
    return 'other'


def __compress_multihops(
        paths_by_source: "Iterable[tuple[RequestSource, Sequence[DirectTransfer]]]",
        sources: "Iterable[RequestSource]",
) -> "Iterator[tuple[RequestSource, Sequence[DirectTransfer]]]":
    # Compress multihop transfers which contain other sources as part of itself.
    # For example: multihop A->B->C and B is a source, compress A->B->C into B->C
    source_rses = {s.rse.id for s in sources}
    seen_source_rses = set()
    for source, path in paths_by_source:
        if len(path) > 1:
            # find the index of the first hop starting from the end which is also a source. Path[0] will always be a source.
            last_source_idx = next((idx for idx, hop in reversed(list(enumerate(path))) if hop.src.rse.id in source_rses), (0, None))
            if last_source_idx > 0:
                path = path[last_source_idx:]

        # Deduplicate paths from same source
        src_rse_id = path[0].src.rse.id
        if src_rse_id not in seen_source_rses:
            seen_source_rses.add(src_rse_id)
            yield source, path


class TransferPathBuilder:
    def __init__(
            self,
            topology: "Topology",
            protocol_factory: ProtocolFactory,
            max_sources: int,
            preparer_mode: bool = False,
            schemes: "Optional[list[str]]" = None,
            failover_schemes: "Optional[list[str]]" = None,
            requested_source_only: bool = False,
    ):
        self.failover_schemes = failover_schemes if failover_schemes is not None else []
        self.schemes = schemes if schemes is not None else []
        self.topology = topology
        self.preparer_mode = preparer_mode
        self.protocol_factory = protocol_factory
        self.max_sources = max_sources
        self.requested_source_only = requested_source_only

        self.definition_by_request_id = {}

    def build_or_return_cached(
            self,
            rws: RequestWithSources,
            sources: "Iterable[RequestSource]",
            *,
            logger: "LoggerFunction" = logging.log,
            session: "Session"
    ) -> "Mapping[RseData, Sequence[DirectTransfer]]":
        """
        Warning: The function currently caches the result for the given request and returns it for later calls
        with the same request id. As a result: it can return more (or less) sources than what is provided in the
        `sources` argument. This is done for performance reasons. As of time of writing, this behavior is not problematic
        for the callers of this method.
        """
        definition = self.definition_by_request_id.get(rws.request_id)
        if definition:
            return definition

        transfer_schemes = self.schemes
        if rws.previous_attempt_id and self.failover_schemes:
            transfer_schemes = self.failover_schemes

        candidate_sources = sources
        if self.requested_source_only and rws.requested_source:
            candidate_sources = [rws.requested_source] if rws.requested_source in sources else []

        if rws.request_type == RequestType.STAGEIN:
            definition = _create_stagein_definitions(
                rws=rws,
                sources=sources,
                limit_dest_schemes=transfer_schemes,
                operation_src='read',
                operation_dest='write',
                protocol_factory=self.protocol_factory
            )
        else:
            definition = _create_transfer_definitions(
                topology=self.topology,
                rws=rws,
                sources=candidate_sources,
                max_sources=self.max_sources,
                multi_source_sources=[] if self.preparer_mode else sources,
                limit_dest_schemes=transfer_schemes,
                operation_src='third_party_copy_read',
                operation_dest='third_party_copy_write',
                domain='wan',
                protocol_factory=self.protocol_factory,
                session=session
            )
        self.definition_by_request_id[rws.request_id] = definition
        return definition


class _SkipSource:
    pass


SKIP_SOURCE = _SkipSource()


class RequestRankingContext:
    """
    Helper class used by SourceRankingStrategy. It allows to store additional request-specific
    context data and access it when handling a specific source of the given request.
    """

    def __init__(self, strategy: "SourceRankingStrategy", rws: "RequestWithSources"):
        self.strategy = strategy
        self.rws = rws

    def apply(self, source: RequestSource) -> "int | _SkipSource":
        verdict = self.strategy.apply(self, source)
        if verdict is None:
            verdict = sys.maxsize
        return verdict


class SourceRankingStrategy:
    """
    Represents a source ranking strategy. Used to order the sources of a request and decide
    which will be the actual source used for the transfer.

    If filter_only is True, any value other than SKIP_SOURCE returned by apply() will be ignored.
    """
    filter_only: bool = False

    def for_request(
            self,
            rws: RequestWithSources,
            sources: "Iterable[RequestSource]",
            *,
            logger: "LoggerFunction" = logging.log,
            session: "Session"
    ) -> "RequestRankingContext":
        return RequestRankingContext(self, rws)

    def apply(self, ctx: RequestRankingContext, source: RequestSource) -> "Optional[int | _SkipSource]":
        """
        Normally, this function will be called indirectly, via self.for_request(...).apply(source).

        It is expected to either return SKIP_SOURCE to signal that this source must be ignored;
        or an integer which gives the cost of the given source under the current strategy
        (smaller cost: higher priority).
        If `None` is returned, it will be interpreted as sys.maxsize (i.e. very low priority).
        This is done to avoid requiring an explicit integer in filter-only strategies.
        """
        pass

    class _ClassNameDescriptor(object):
        """
        Automatically set the external_name of the strategy to the class name.
        """
        def __get__(self, obj, objtype=None):
            if objtype is not None:
                return objtype.__name__
            return type(obj).__name__

    external_name = _ClassNameDescriptor()


class SourceFilterStrategy(SourceRankingStrategy):
    filter_only = True


class EnforceSourceRSEExpression(SourceFilterStrategy):

    class _RankingContext(RequestRankingContext):
        def __init__(self, strategy: "SourceRankingStrategy", rws: "RequestWithSources", allowed_source_rses: "Optional[set[str]]"):
            super().__init__(strategy, rws)
            self.allowed_source_rses = allowed_source_rses

    def for_request(
            self,
            rws: RequestWithSources,
            sources: "Iterable[RequestSource]",
            *,
            logger: "LoggerFunction" = logging.log,
            session: "Session"
    ) -> "RequestRankingContext":
        # parse source expression
        allowed_source_rses = None
        source_replica_expression = rws.attributes.get('source_replica_expression', None)
        if source_replica_expression:
            try:
                parsed_rses = parse_expression(source_replica_expression, session=session)
            except InvalidRSEExpression as error:
                logger(logging.ERROR, "%s: Invalid RSE exception %s: %s", rws.request_id, source_replica_expression, str(error))
                allowed_source_rses = set()
            else:
                allowed_source_rses = {x['id'] for x in parsed_rses}
        return self._RankingContext(self, rws, allowed_source_rses)

    def apply(self, ctx: RequestRankingContext, source: RequestSource) -> "Optional[int | _SkipSource]":
        ctx = cast(EnforceSourceRSEExpression._RankingContext, ctx)
        if ctx.allowed_source_rses is not None and source.rse.id not in ctx.allowed_source_rses:
            return SKIP_SOURCE


class SkipRestrictedRSEs(SourceFilterStrategy):

    def __init__(self, admin_accounts: "Optional[set[InternalAccount]]" = None):
        super().__init__()
        self.admin_accounts = admin_accounts if admin_accounts is not None else []

    def apply(self, ctx: RequestRankingContext, source: RequestSource) -> "Optional[int | _SkipSource]":
        if source.rse.attributes.get('restricted_read') and ctx.rws.account not in self.admin_accounts:
            return SKIP_SOURCE


class SkipBlocklistedRSEs(SourceFilterStrategy):

    def __init__(self, topology: "Topology"):
        super().__init__()
        self.topology = topology

    def apply(self, ctx: RequestRankingContext, source: RequestSource) -> "Optional[int | _SkipSource]":
        # Ignore blocklisted RSEs
        if not source.rse.columns['availability_read'] and not self.topology.ignore_availability:
            return SKIP_SOURCE


class EnforceStagingBuffer(SourceFilterStrategy):
    def apply(self, ctx: RequestRankingContext, source: RequestSource) -> "Optional[int | _SkipSource]":
        # For staging requests, the staging_buffer attribute must be correctly set
        if ctx.rws.request_type == RequestType.STAGEIN and source.rse.attributes.get('staging_buffer') != ctx.rws.dest_rse.name:
            return SKIP_SOURCE


class RestrictTapeSources(SourceFilterStrategy):
    def apply(self, ctx: RequestRankingContext, source: RequestSource) -> "Optional[int | _SkipSource]":
        # Ignore tape sources if they are not desired
        if source.rse.is_tape_or_staging_required() and not ctx.rws.attributes.get("allow_tape_source", True):
            return SKIP_SOURCE


class HighestAdjustedRankingFirst(SourceRankingStrategy):
    def apply(self, ctx: RequestRankingContext, source: RequestSource) -> "Optional[int | _SkipSource]":
        source_ranking_penalty = 1 if source.rse.is_tape_or_staging_required() else 0
        return - source.ranking + source_ranking_penalty


class PreferDiskOverTape(SourceRankingStrategy):
    def apply(self, ctx: RequestRankingContext, source: RequestSource) -> "Optional[int | _SkipSource]":
        return int(source.rse.is_tape_or_staging_required())  # rely on the fact that False < True


class PathDistance(SourceRankingStrategy):

    class _RankingContext(RequestRankingContext):
        def __init__(self, strategy: "SourceRankingStrategy", rws: "RequestWithSources", paths_for_rws: "Mapping[RseData, Sequence[DirectTransfer]]"):
            super().__init__(strategy, rws)
            self.paths_for_rws = paths_for_rws

    def __init__(self, transfer_path_builder: TransferPathBuilder):
        super().__init__()
        self.transfer_path_builder = transfer_path_builder

    def for_request(
            self,
            rws: RequestWithSources,
            sources: "Iterable[RequestSource]",
            *,
            logger: "LoggerFunction" = logging.log,
            session: "Session"
    ) -> "RequestRankingContext":
        paths_for_rws = self.transfer_path_builder.build_or_return_cached(rws, sources, logger=logger, session=session)
        return PathDistance._RankingContext(self, rws, paths_for_rws)

    def apply(self, ctx: RequestRankingContext, source: RequestSource) -> "Optional[int | _SkipSource]":
        path = cast(PathDistance._RankingContext, ctx).paths_for_rws.get(source.rse)
        if not path:
            return SKIP_SOURCE
        return path[0].src.distance


class PreferSingleHop(PathDistance):
    def apply(self, ctx: RequestRankingContext, source: RequestSource) -> "Optional[int | _SkipSource]":
        path = cast(PathDistance._RankingContext, ctx).paths_for_rws.get(source.rse)
        if not path:
            return SKIP_SOURCE
        return int(len(path) > 1)


class FailureRate(SourceRankingStrategy):
    """
    A source ranking strategy that ranks source nodes based on their failure rates for the past hour. Failure rate is
    calculated by dividing files failed by files attempted.
    """
    class _FailureRateStat:
        def __init__(self) -> None:
            self.files_done = 0
            self.files_failed = 0

        def incorporate_stat(self, stat: "Mapping[str, int]") -> None:
            self.files_done += stat['files_done']
            self.files_failed += stat['files_failed']

        def get_failure_rate(self) -> int:
            files_attempted = self.files_done + self.files_failed

            # If no files have been sent yet, return failure rate as 0
            if files_attempted == 0:
                return 0

            return int((self.files_failed / files_attempted) * 10000)

    def __init__(self, stats_manager: "request_core.TransferStatsManager") -> None:
        super().__init__()
        self.source_stats = {}

        for stat in stats_manager.load_totals(
            datetime.datetime.utcnow() - datetime.timedelta(hours=1),
            by_activity=False
        ):
            self.source_stats.setdefault(stat['src_rse_id'], self._FailureRateStat()).incorporate_stat(stat)

    def apply(self, ctx: RequestRankingContext, source: RequestSource) -> "Optional[int | _SkipSource]":
        failure_rate = cast(FailureRate, ctx.strategy).source_stats.get(source.rse.id, self._FailureRateStat()).get_failure_rate()
        return failure_rate


class SkipSchemeMissmatch(PathDistance):
    filter_only = True

    def apply(self, ctx: RequestRankingContext, source: RequestSource) -> "Optional[int | _SkipSource]":
        path = cast(PathDistance._RankingContext, ctx).paths_for_rws.get(source.rse)
        # path == None means that there is no path;
        # path == [] means that a path exists (according to distances) but cannot be used (scheme missmatch)
        if path is not None and not path:
            return SKIP_SOURCE


class SkipIntermediateTape(PathDistance):
    filter_only = True

    def apply(self, ctx: RequestRankingContext, source: RequestSource) -> "Optional[int | _SkipSource]":
        # Discard multihop transfers which contain a tape source as an intermediate hop
        path = cast(PathDistance._RankingContext, ctx).paths_for_rws.get(source.rse)
        if path and any(transfer.src.rse.is_tape_or_staging_required() for transfer in path[1:]):
            return SKIP_SOURCE


@transactional_session
def build_transfer_paths(
        topology: "Topology",
        protocol_factory: "ProtocolFactory",
        requests_with_sources: "Iterable[RequestWithSources]",
        admin_accounts: "Optional[set[InternalAccount]]" = None,
        schemes: "Optional[list[str]]" = None,
        failover_schemes: "Optional[list[str]]" = None,
        max_sources: int = 4,
        transfertools: "Optional[list[str]]" = None,
        requested_source_only: bool = False,
        preparer_mode: bool = False,
        *,
        session: "Session",
        logger: "Callable" = logging.log,
):
    """
    For each request, find all possible transfer paths from its sources, which respect the
    constraints enforced by the request (attributes, type, etc) and the arguments of this function

    build a multi-source transfer if possible: The scheme compatibility is important for multi-source transfers.
    We iterate again over the single-hop sources and build a new transfer definition while enforcing the scheme compatibility
    with the initial source.

    Each path is a list of hops. Each hop is a transfer definition.
    """
    transfer_path_builder = TransferPathBuilder(
        topology=topology,
        schemes=schemes,
        failover_schemes=failover_schemes,
        protocol_factory=protocol_factory,
        max_sources=max_sources,
        preparer_mode=preparer_mode,
        requested_source_only=requested_source_only,
    )

    stats_manager = request_core.TransferStatsManager()

    available_strategies = {
        EnforceSourceRSEExpression.external_name: lambda: EnforceSourceRSEExpression(),
        SkipBlocklistedRSEs.external_name: lambda: SkipBlocklistedRSEs(topology=topology),
        SkipRestrictedRSEs.external_name: lambda: SkipRestrictedRSEs(admin_accounts=admin_accounts),
        EnforceStagingBuffer.external_name: lambda: EnforceStagingBuffer(),
        RestrictTapeSources.external_name: lambda: RestrictTapeSources(),
        SkipSchemeMissmatch.external_name: lambda: SkipSchemeMissmatch(transfer_path_builder=transfer_path_builder),
        SkipIntermediateTape.external_name: lambda: SkipIntermediateTape(transfer_path_builder=transfer_path_builder),
        HighestAdjustedRankingFirst.external_name: lambda: HighestAdjustedRankingFirst(),
        PreferDiskOverTape.external_name: lambda: PreferDiskOverTape(),
        PathDistance.external_name: lambda: PathDistance(transfer_path_builder=transfer_path_builder),
        PreferSingleHop.external_name: lambda: PreferSingleHop(transfer_path_builder=transfer_path_builder),
        FailureRate.external_name: lambda: FailureRate(stats_manager=stats_manager),
    }

    default_strategies = [
        EnforceSourceRSEExpression.external_name,
        SkipBlocklistedRSEs.external_name,
        SkipRestrictedRSEs.external_name,
        EnforceStagingBuffer.external_name,
        RestrictTapeSources.external_name,
        # Without the SkipSchemeMissmatch strategy, requests will never be transitioned to the
        # RequestState.MISMATCH_SCHEME state. It _MUST_ be placed before the other Path-based strategies.
        SkipSchemeMissmatch.external_name,
        SkipIntermediateTape.external_name,
        HighestAdjustedRankingFirst.external_name,
        PreferDiskOverTape.external_name,
        PathDistance.external_name,
        PreferSingleHop.external_name,
    ]
    strategy_names = config_get_list('transfers', 'source_ranking_strategies', default=default_strategies)

    try:
        strategies = list(available_strategies[name]() for name in strategy_names)
    except KeyError:
        logger(logging.ERROR, "One of the configured source_ranking_strategies doesn't exist %s", strategy_names, exc_info=True)
        raise

    if admin_accounts is None:
        admin_accounts = set()

    # Do not print full source RSE list for DIDs which have many sources. Otherwise we fill the monitoring
    # storage with data which has little to no benefit. This log message is unlikely to help debugging
    # transfers issues when there are many sources, but can be very useful for small number of sources.
    num_sources_in_logs = 4

    candidate_paths_by_request_id, reqs_no_source, reqs_only_tape_source, reqs_scheme_mismatch = {}, set(), set(), set()
    reqs_unsupported_transfertool = set()
    for rws in requests_with_sources:

        rws.dest_rse.ensure_loaded(load_name=True, load_info=True, load_attributes=True, load_columns=True, session=session)
        all_sources = rws.sources
        for source in all_sources:
            source.rse.ensure_loaded(load_name=True, load_info=True, load_attributes=True, load_columns=True, session=session)

        # Assume request doesn't have any sources. Will be removed later if sources are found.
        reqs_no_source.add(rws.request_id)
        if not all_sources:
            logger(logging.INFO, '%s: has no sources. Skipping.', rws)
            continue

        logger(logging.DEBUG, '%s: Working on %d sources%s: %s%s',
               rws,
               len(all_sources),
               f' (priority {rws.requested_source.rse})' if requested_source_only and rws.requested_source else '',
               ','.join('{}:{}:{}'.format(src.rse, src.ranking, src.distance) for src in all_sources[:num_sources_in_logs]),
               '... and %d others' % (len(all_sources) - num_sources_in_logs) if len(all_sources) > num_sources_in_logs else '')

        # Check if destination is blocked
        if not (topology.ignore_availability or rws.dest_rse.columns['availability_write']):
            logger(logging.WARNING, '%s: dst RSE is blocked for write. Will skip the submission of new jobs', rws.request_id)
            continue
        if rws.account not in admin_accounts and rws.dest_rse.attributes.get('restricted_write'):
            logger(logging.WARNING, '%s: dst RSE is restricted for write. Will skip the submission', rws.request_id)
            continue

        if rws.transfertool and transfertools and rws.transfertool not in transfertools:
            # The request explicitly asks for a transfertool which this submitter doesn't support
            logger(logging.INFO, '%s: unsupported transfertool. Skipping.', rws.request_id)
            reqs_unsupported_transfertool.add(rws.request_id)
            reqs_no_source.remove(rws.request_id)
            continue

        # For each strategy name, gives the sources which were rejected by it
        rejected_sources = defaultdict(list)
        # Cost of each accepted source (lists of ordered costs: one for each ranking strategy)
        cost_vectors = {s: [] for s in rws.sources}
        for strategy in strategies:
            sources = list(cost_vectors)
            if not sources:
                # All sources where filtered by previous strategies. It's worthless to continue.
                break
            rws_strategy = strategy.for_request(rws, sources, logger=logger, session=session)
            for source in sources:
                verdict = rws_strategy.apply(source)
                if verdict is SKIP_SOURCE:
                    rejected_sources[strategy.external_name].append(source)
                    cost_vectors.pop(source)
                elif not strategy.filter_only:
                    cost_vectors[source].append(verdict)

        transfers_by_rse = transfer_path_builder.build_or_return_cached(rws, cost_vectors, logger=logger, session=session)
        candidate_paths = ((s, transfers_by_rse[s.rse]) for s, _ in sorted(cost_vectors.items(), key=operator.itemgetter(1)))
        if not preparer_mode:
            candidate_paths = __compress_multihops(candidate_paths, all_sources)
        candidate_paths = list(candidate_paths)

        ordered_sources_log = ', '.join(
            f"{s.rse}:{':'.join(str(e) for e in cost_vectors[s])}"
            f"{'(actual source ' + str(path[0].src.rse) + ')' if s.rse != path[0].src.rse else ''}"
            f"{'(multihop)' if len(path) > 1 else ''}"
            for s, path in candidate_paths[:num_sources_in_logs]
        )
        if len(candidate_paths) > num_sources_in_logs:
            ordered_sources_log += '... and %d others' % (len(candidate_paths) - num_sources_in_logs)
        filtered_rses_log = ''
        for strategy_name, sources in rejected_sources.items():
            filtered_rses_log += f'; {len(sources)} dropped by strategy "{strategy_name}": '
            filtered_rses_log += ','.join(str(s.rse) for s in sources[:num_sources_in_logs])
            if len(sources) > num_sources_in_logs:
                filtered_rses_log += '... and %d others' % (len(sources) - num_sources_in_logs)
        logger(logging.INFO, '%s: %d ordered sources: %s%s', rws, len(candidate_paths), ordered_sources_log, filtered_rses_log)

        if not candidate_paths:
            # It can happen that some sources are skipped because they are TAPE, and others because
            # of scheme mismatch. However, we can only have one state in the database. I picked to
            # prioritize setting only_tape_source without any particular reason.
            if RestrictTapeSources.external_name in rejected_sources:
                logger(logging.DEBUG, '%s: Only tape sources found' % rws.request_id)
                reqs_only_tape_source.add(rws.request_id)
                reqs_no_source.remove(rws.request_id)
            elif SkipSchemeMissmatch.external_name in rejected_sources:
                logger(logging.DEBUG, '%s: Scheme mismatch detected' % rws.request_id)
                reqs_scheme_mismatch.add(rws.request_id)
                reqs_no_source.remove(rws.request_id)
            else:
                logger(logging.DEBUG, '%s: No candidate path found' % rws.request_id)
            continue

        candidate_paths_by_request_id[rws.request_id] = [path for _, path in candidate_paths]
        reqs_no_source.remove(rws.request_id)

    return candidate_paths_by_request_id, reqs_no_source, reqs_scheme_mismatch, reqs_only_tape_source, reqs_unsupported_transfertool


def __add_compatible_schemes(schemes, allowed_schemes):
    """
    Add the compatible schemes to a list of schemes
    :param schemes:           Schemes as input.
    :param allowed_schemes:   Allowed schemes, only these can be in the output.
    :returns:                 List of schemes
    """

    return_schemes = []
    for scheme in schemes:
        if scheme in allowed_schemes:
            return_schemes.append(scheme)
            for scheme_map_scheme in constants.SCHEME_MAP.get(scheme, []):
                if scheme_map_scheme not in allowed_schemes:
                    continue
                else:
                    return_schemes.append(scheme_map_scheme)
    return list(set(return_schemes))


@read_session
def list_transfer_admin_accounts(*, session: "Session") -> "set[InternalAccount]":
    """
    List admin accounts and cache the result in memory
    """

    result = REGION_ACCOUNTS.get('transfer_admin_accounts')
    if isinstance(result, NoValue):
        result = [acc['account'] for acc in list_accounts(filter_={'admin': True}, session=session)]
        REGION_ACCOUNTS.set('transfer_admin_accounts', result)
    return set(result)


def update_transfer_priority(transfers_to_update, logger=logging.log):
    """
    Update transfer priority in fts

    :param transfers_to_update: dict {external_host1: {transfer_id1: priority, transfer_id2: priority, ...}, ...}
    :param logger: decorated logger instance
    """

    for external_host, priority_by_transfer_id in transfers_to_update.items():
        transfertool_obj = FTS3Transfertool(external_host=external_host)
        for transfer_id, priority in priority_by_transfer_id.items():
            res = transfertool_obj.update_priority(transfer_id=transfer_id, priority=priority)
            logger(logging.DEBUG, "Updated transfer %s priority in transfertool to %s: %s" % (transfer_id, priority, res['http_message']))


def cancel_transfers(transfers_to_cancel, logger=logging.log):
    """
    Cancel transfers in fts

    :param transfers_to_cancel: dict {external_host1: {transfer_id1, transfer_id2}, external_host2: [...], ...}
    :param logger: decorated logger instance
    """

    for external_host, transfer_ids in transfers_to_cancel.items():
        transfertool_obj = FTS3Transfertool(external_host=external_host)
        for transfer_id in transfer_ids:
            try:
                transfertool_obj.cancel(transfer_ids=[transfer_id])
                logger(logging.DEBUG, "Cancelled FTS3 transfer %s on %s" % (transfer_id, transfertool_obj))
            except Exception as error:
                logger(logging.WARNING, 'Could not cancel FTS3 transfer %s on %s: %s' % (transfer_id, transfertool_obj, str(error)))


@METRICS.count_it
def cancel_transfer(transfertool_obj, transfer_id):
    """
    Cancel a transfer based on external transfer id.

    :param transfertool_obj: Transfertool object to be used for cancellation.
    :param transfer_id:      External-ID as a 32 character hex string.
    """

    try:
        transfertool_obj.cancel(transfer_ids=[transfer_id])
    except Exception:
        raise RucioException('Could not cancel FTS3 transfer %s on %s: %s' % (transfer_id, transfertool_obj, traceback.format_exc()))


@transactional_session
def prepare_transfers(
        candidate_paths_by_request_id: "dict[str, list[list[DirectTransfer]]]",
        logger: "LoggerFunction" = logging.log,
        transfertools: "Optional[list[str]]" = None,
        *,
        session: "Session",
) -> tuple[list[str], list[str]]:
    """
    Update transfer requests according to preparer settings.
    """

    reqs_no_transfertool = []
    updated_reqs = []
    for request_id, candidate_paths in candidate_paths_by_request_id.items():
        selected_source = None
        transfertool = None
        rws = candidate_paths[0][-1].rws

        for candidate_path in candidate_paths:
            source = candidate_path[0].src
            all_hops_ok = True
            transfertool = None
            for hop in candidate_path:
                common_transfertools = get_supported_transfertools(hop.src.rse, hop.dst.rse, transfertools=transfertools, session=session)
                if not common_transfertools:
                    all_hops_ok = False
                    break
                # We need the last hop transfertool. Always prioritize fts3 if it exists.
                transfertool = 'fts3' if 'fts3' in common_transfertools else common_transfertools.pop()

            if all_hops_ok and transfertool:
                selected_source = source
                break

        if not selected_source:
            reqs_no_transfertool.append(request_id)
            logger(logging.WARNING, '%s: all available sources were filtered', rws)
            continue

        update_dict: "dict[Any, Any]" = {
            models.Request.state.name: _throttler_request_state(
                activity=rws.activity,
                source_rse=selected_source.rse,
                dest_rse=rws.dest_rse,
                session=session,
            ),
            models.Request.source_rse_id.name: selected_source.rse.id,
        }
        if transfertool:
            update_dict[models.Request.transfertool.name] = transfertool

        request_core.update_request(rws.request_id, session=session, **update_dict)
        updated_reqs.append(request_id)

    return updated_reqs, reqs_no_transfertool


@stream_session
def applicable_rse_transfer_limits(
        source_rse: "Optional[RseData]" = None,
        dest_rse: "Optional[RseData]" = None,
        activity: "Optional[str]" = None,
        *,
        session: "Session",
):
    """
    Find all RseTransferLimits which must be enforced for transfers between source and destination RSEs for the given activity.
    """
    source_limits = {}
    if source_rse:
        source_limits = source_rse.ensure_loaded(load_transfer_limits=True, session=session).transfer_limits.get(TransferLimitDirection.SOURCE, {})
    dest_limits = {}
    if dest_rse:
        dest_limits = dest_rse.ensure_loaded(load_transfer_limits=True, session=session).transfer_limits.get(TransferLimitDirection.DESTINATION, {})

    if activity is not None:
        limit = source_limits.get(activity)
        if limit:
            yield limit

        limit = dest_limits.get(activity)
        if limit:
            yield limit

    # get "all_activities" limits
    limit = source_limits.get(None)
    if limit:
        yield limit

    limit = dest_limits.get(None)
    if limit:
        yield limit


def _throttler_request_state(activity, source_rse, dest_rse, *, session: "Session") -> RequestState:
    """
    Takes request attributes to return a new state for the request
    based on throttler settings. Always returns QUEUED,
    if the throttler mode is not set.
    """
    limit_found = False
    if any(applicable_rse_transfer_limits(activity=activity, source_rse=source_rse, dest_rse=dest_rse, session=session)):
        limit_found = True

    return RequestState.WAITING if limit_found else RequestState.QUEUED


@read_session
def get_supported_transfertools(
        source_rse: "RseData",
        dest_rse: "RseData",
        transfertools: "Optional[list[str]]" = None,
        *,
        session: "Session",
) -> set[str]:

    if not transfertools:
        transfertools = list(TRANSFERTOOL_CLASSES_BY_NAME)

    source_rse.ensure_loaded(load_attributes=True, session=session)
    dest_rse.ensure_loaded(load_attributes=True, session=session)

    result = set()
    for tt_name in transfertools:
        tt_class = TRANSFERTOOL_CLASSES_BY_NAME.get(tt_name)
        if tt_class and tt_class.can_perform_transfer(source_rse, dest_rse):
            result.add(tt_name)
    return result
