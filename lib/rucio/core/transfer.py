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
import re
import time
import traceback
from typing import TYPE_CHECKING

from dogpile.cache import make_region
from dogpile.cache.api import NoValue
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from rucio.common import constants
from rucio.common.config import config_get
from rucio.common.constants import SUPPORTED_PROTOCOLS
from rucio.common.exception import (InvalidRSEExpression,
                                    RequestNotFound, RSEProtocolNotSupported,
                                    RucioException, UnsupportedOperation)
from rucio.common.utils import construct_surl
from rucio.core import did, message as message_core, request as request_core
from rucio.core.account import list_accounts
from rucio.core.monitor import record_counter
from rucio.core.request import set_request_state, RequestWithSources, RequestSource
from rucio.core.rse_expression_parser import parse_expression
from rucio.db.sqla import models
from rucio.db.sqla.constants import DIDType, RequestState, RequestType
from rucio.db.sqla.session import read_session, transactional_session
from rucio.rse import rsemanager as rsemgr
from rucio.transfertool.fts3 import FTS3Transfertool
from rucio.transfertool.globus import GlobusTransferTool
from rucio.transfertool.mock import MockTransfertool

if TYPE_CHECKING:
    from typing import Any, Callable, Dict, Generator, Iterable, List, Optional, Set, Tuple
    from sqlalchemy.orm import Session
    from rucio.common.types import InternalAccount
    from rucio.core.rse import RseData
    from rucio.core.topology import Topology

    LoggerFunction = Callable[..., Any]

"""
The core transfer.py is specifically for handling transfer-requests, thus requests
where the external_id is already known.
Requests accessed by request_id  are covered in the core request.py
"""

REGION_ACCOUNTS = make_region().configure('dogpile.cache.memory', expiration_time=600)

WEBDAV_TRANSFER_MODE = config_get('conveyor', 'webdav_transfer_mode', False, None)

DEFAULT_MULTIHOP_TOMBSTONE_DELAY = int(datetime.timedelta(hours=2).total_seconds())

TRANSFERTOOL_CLASSES_BY_NAME = {
    FTS3Transfertool.external_name: FTS3Transfertool,
    GlobusTransferTool.external_name: GlobusTransferTool,
    MockTransfertool.external_name: MockTransfertool,
}


class TransferDestination:
    def __init__(self, rse_data, scheme):
        self.rse = rse_data
        self.scheme = scheme

    def __str__(self):
        return "dst_rse={}".format(self.rse)


class ProtocolFactory:
    """
    Creates and caches protocol objects. Allowing to reuse them.
    """
    def __init__(self):
        self.protocols = {}

    def protocol(self, rse_data, scheme, operation):
        protocol_key = '%s_%s_%s' % (operation, rse_data.id, scheme)
        protocol = self.protocols.get(protocol_key)
        if not protocol:
            protocol = rsemgr.create_protocol(rse_data.info, operation, scheme)
            self.protocols[protocol_key] = protocol
        return protocol


class DirectTransferDefinition:
    """
    The configuration for a direct (non-multi-hop) transfer. It can be a multi-source transfer.

    The class wraps the legacy dict-based transfer definition to maintain compatibility with existing code
    during the migration.
    """
    def __init__(self, source: RequestSource, destination: TransferDestination, rws: RequestWithSources,
                 protocol_factory: ProtocolFactory, operation_src: str, operation_dest: str):
        self.sources = [source]
        self.destination = destination

        self.rws = rws
        self.protocol_factory = protocol_factory
        self.operation_src = operation_src
        self.operation_dest = operation_dest

        self._dest_url = None
        self._legacy_sources = None

    def __str__(self):
        return '{sources}--{request_id}->{destination}'.format(
            sources=','.join([str(s.rse) for s in self.sources]),
            request_id=self.rws.request_id or '',
            destination=self.dst.rse
        )

    @property
    def src(self):
        return self.sources[0]

    @property
    def dst(self):
        return self.destination

    @property
    def dest_url(self):
        if not self._dest_url:
            self._dest_url = self._generate_dest_url(self.dst, self.rws, self.protocol_factory, self.operation_dest)
        return self._dest_url

    @property
    def legacy_sources(self):
        if not self._legacy_sources:
            self._legacy_sources = [
                (src.rse.name,
                 self._generate_source_url(src,
                                           self.dst,
                                           rws=self.rws,
                                           protocol_factory=self.protocol_factory,
                                           operation=self.operation_src),
                 src.rse.id,
                 src.source_ranking)
                for src in self.sources
            ]
        return self._legacy_sources

    @property
    def use_ipv4(self):
        # If any source or destination rse is ipv4 only
        return self.dst.rse.attributes.get('use_ipv4', False) or any(src.rse.attributes.get('use_ipv4', False)
                                                                     for src in self.sources)

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


class StageinTransferDefinition(DirectTransferDefinition):
    """
    A definition of a transfer which triggers a stagein operation.
        - The source and destination url are identical
        - must be from TAPE to non-TAPE RSE
        - can only have one source
    """
    def __init__(self, source, destination, rws, protocol_factory, operation_src, operation_dest):
        if not source.rse.is_tape() or destination.rse.is_tape():
            raise RucioException("Stageing request {} must be from TAPE to DISK rse. Got {} and {}.".format(rws, source, destination))
        super().__init__(source, destination, rws, protocol_factory, operation_src, operation_dest)

    @property
    def dest_url(self):
        if not self._dest_url:
            self._dest_url = self.src.url if self.src.url else self._generate_source_url(self.src,
                                                                                         self.dst,
                                                                                         rws=self.rws,
                                                                                         protocol_factory=self.protocol_factory,
                                                                                         operation=self.operation_dest)
        return self._dest_url

    @property
    def legacy_sources(self):
        if not self._legacy_sources:
            self._legacy_sources = [(
                self.src.rse.name,
                self.dest_url,  # Source and dest url is the same for stagein requests
                self.src.rse.id,
                self.src.source_ranking
            )]
        return self._legacy_sources


def transfer_path_str(transfer_path: "List[DirectTransferDefinition]") -> str:
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
        transfer: "DirectTransferDefinition",
        external_host: str,
        logger: "Callable",
        session: "Optional[Session]" = None,
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
                                                                                                          transfer.legacy_sources,
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


def ensure_db_sources(
        transfer_path: "List[DirectTransferDefinition]",
        logger: "Callable",
        session: "Optional[Session]" = None,
):
    """
    Ensure the needed DB source objects exist
    """

    desired_sources = []
    for transfer in transfer_path:

        for src_rse, src_url, src_rse_id, rank in transfer.legacy_sources:
            common_source_attrs = {
                "scope": transfer.rws.scope,
                "name": transfer.rws.name,
                "rse_id": src_rse_id,
                "dest_rse_id": transfer.dst.rse.id,
                "ranking": rank if rank else 0,
                "bytes": transfer.rws.byte_count,
                "url": src_url,
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
def set_transfers_state(transfers, state, submitted_at, external_host, external_id, logger, session=None):
    """
    Update the transfer info of a request.
    :param transfers:  Dictionary containing request transfer info.
    :param session:    Database session to use.
    """

    logger(logging.INFO, 'Setting state(%s), external_host(%s) and eid(%s) for transfers: %s',
           state.name, external_host, external_id, ', '.join(t.rws.request_id for t in transfers))
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
                    'state': state,
                    'external_id': external_id,
                    'external_host': external_host,
                    'source_rse_id': transfer.src.rse.id,
                    'submitted_at': submitted_at,
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
def mark_transfer_lost(request, session=None, logger=logging.log):
    new_state = RequestState.LOST
    reason = "The FTS job lost"

    err_msg = request_core.get_transfer_error(new_state, reason)
    set_request_state(request['id'], state=new_state, external_id=request['external_id'], err_msg=err_msg, session=session, logger=logger)

    request_core.add_monitor_message(new_state=new_state, request=request, additional_fields={'reason': reason}, session=session)


@transactional_session
def set_transfer_update_time(external_host, transfer_id, update_time=datetime.datetime.utcnow(), session=None):
    """
    Update the state of a request. Fails silently if the transfer_id does not exist.
    :param external_host:  Selected external host as string in format protocol://fqdn:port
    :param transfer_id:    External transfer job id as a string.
    :param update_time:    Time stamp.
    :param session:        Database session to use.
    """

    record_counter('core.request.set_transfer_update_time')

    try:
        stmt = update(
            models.Request
        ).where(
            models.Request.external_id == transfer_id,
            models.Request.state == RequestState.SUBMITTED
        ).execution_options(
            synchronize_session=False
        ).values(
            updated_at=update_time
        )
        rowcount = session.executet(stmt).rowcount
    except IntegrityError as error:
        raise RucioException(error.args)

    if not rowcount:
        raise UnsupportedOperation("Transfer %s doesn't exist or its status is not submitted." % transfer_id)


@transactional_session
def touch_transfer(external_host, transfer_id, session=None):
    """
    Update the timestamp of requests in a transfer. Fails silently if the transfer_id does not exist.
    :param request_host:   Name of the external host.
    :param transfer_id:    External transfer job id as a string.
    :param session:        Database session to use.
    """

    record_counter('core.request.touch_transfer')

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


@read_session
def __create_transfer_definitions(
        topology: "Topology",
        protocol_factory: ProtocolFactory,
        rws: RequestWithSources,
        sources: "List[RequestSource]",
        multi_source_sources: "List[RequestSource]",
        limit_dest_schemes: "List[str]",
        operation_src: str,
        operation_dest: str,
        domain: str,
        session: "Optional[Session]" = None,
) -> "Dict[str, List[DirectTransferDefinition]]":
    """
    Find the all paths from sources towards the destination of the given transfer request.
    Create the transfer definitions for each point-to-point transfer (multi-source, when possible)
    """
    inbound_links_by_node = {}
    shortest_paths = topology.search_shortest_paths(source_rse_ids=[s.rse.id for s in sources], dest_rse_id=rws.dest_rse.id,
                                                    operation_src=operation_src, operation_dest=operation_dest, domain=domain,
                                                    limit_dest_schemes=limit_dest_schemes,
                                                    inbound_links_by_node=inbound_links_by_node, session=session)

    transfers_by_source = {}
    sources_by_rse_id = {s.rse.id: s for s in sources}
    paths_by_source = {sources_by_rse_id[rse_id]: path for rse_id, path in shortest_paths.items()}
    for source, list_hops in paths_by_source.items():
        transfer_path = []
        for hop in list_hops:
            hop_src_rse = topology.rse_collection[hop['source_rse_id']]
            hop_dst_rse = topology.rse_collection[hop['dest_rse_id']]
            src = RequestSource(
                rse_data=hop_src_rse,
                file_path=source.file_path if hop_src_rse == source.rse else None,
                source_ranking=source.source_ranking if hop_src_rse == source.rse else 0,
                distance_ranking=hop['cumulated_distance'] if hop_src_rse == source.rse else hop['hop_distance'],
                scheme=hop['source_scheme'],
            )
            dst = TransferDestination(
                rse_data=hop_dst_rse,
                scheme=hop['dest_scheme'],
            )
            hop_definition = DirectTransferDefinition(
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
                    dest_rse_data=hop_dst_rse,
                    account=rws.account,
                    retry_count=0,
                    priority=rws.priority,
                    transfertool=rws.transfertool,
                ),
                protocol_factory=protocol_factory,
            )

            transfer_path.append(hop_definition)
        transfers_by_source[source.rse.id] = transfer_path

    # create multi-source transfers: add additional sources if possible
    for transfer_path in transfers_by_source.values():
        if len(transfer_path) == 1 and not transfer_path[0].src.rse.is_tape():
            # Multiple single-hop DISK rses can be used together in "multi-source" transfers
            #
            # Try adding additional single-hop DISK rses sources to the transfer
            inbound_links = inbound_links_by_node[transfer_path[0].dst.rse.id]
            main_source_schemes = __add_compatible_schemes(schemes=[transfer_path[0].dst.scheme], allowed_schemes=SUPPORTED_PROTOCOLS)
            added_sources = 0
            for source in sorted(multi_source_sources, key=lambda s: (-s.source_ranking, s.distance_ranking)):
                if added_sources >= 5:
                    break

                if source.rse.id not in inbound_links:
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
                        rse_data=source.rse,
                        file_path=source.file_path,
                        source_ranking=source.source_ranking,
                        distance_ranking=inbound_links[source.rse.id],
                        scheme=matching_scheme[1],
                    )
                )
                added_sources += 1
    return transfers_by_source


def __create_stagein_definitions(
        rws: RequestWithSources,
        sources: "List[RequestSource]",
        limit_dest_schemes: "List[str]",
        operation_src: str,
        operation_dest: str,
        protocol_factory: ProtocolFactory,
) -> "Dict[str, List[StageinTransferDefinition]]":
    """
    for each source, create a single-hop transfer path with a one stageing definition inside
    """
    transfers_by_source = {
        source.rse.id: [
            StageinTransferDefinition(
                source=RequestSource(
                    rse_data=source.rse,
                    file_path=source.file_path,
                    url=source.url,
                    scheme=limit_dest_schemes,
                ),
                destination=TransferDestination(
                    rse_data=rws.dest_rse,
                    scheme=limit_dest_schemes,
                ),
                operation_src=operation_src,
                operation_dest=operation_dest,
                rws=rws,
                protocol_factory=protocol_factory,
            )

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


def __filter_multihops_with_intermediate_tape(candidate_paths: "Iterable[List[DirectTransferDefinition]]") -> "Generator[List[DirectTransferDefinition]]":
    # Discard multihop transfers which contain a tape source as an intermediate hop
    for path in candidate_paths:
        if any(transfer.src.rse.is_tape_or_staging_required() for transfer in path[1:]):
            pass
        else:
            yield path


def __compress_multihops(
        candidate_paths: "Iterable[List[DirectTransferDefinition]]",
        sources: "Iterable[RequestSource]",
) -> "Generator[List[DirectTransferDefinition]]":
    # Compress multihop transfers which contain other sources as part of itself.
    # For example: multihop A->B->C and B is a source, compress A->B->C into B->C
    source_rses = {s.rse.id for s in sources}
    seen_source_rses = set()
    for path in candidate_paths:
        if len(path) > 1:
            # find the index of the first hop starting from the end which is also a source. Path[0] will always be a source.
            last_source_idx = next((idx for idx, hop in reversed(list(enumerate(path))) if hop.src.rse.id in source_rses), (0, None))
            if last_source_idx > 0:
                path = path[last_source_idx:]

        # Deduplicate paths from same source
        src_rse_id = path[0].src.rse.id
        if src_rse_id not in seen_source_rses:
            seen_source_rses.add(src_rse_id)
            yield path


def __sort_paths(candidate_paths: "Iterable[List[DirectTransferDefinition]]") -> "Generator[List[DirectTransferDefinition]]":

    def __transfer_order_key(transfer_path):
        # Reduce the priority of the tape sources. If there are any disk sources,
        # they must fail twice (1 penalty + 1 disk preferred over tape) before a tape will even be tried
        source_ranking_penalty = 1 if transfer_path[0].src.rse.is_tape_or_staging_required() else 0
        # higher source_ranking first,
        # on equal source_ranking, prefer DISK over TAPE
        # on equal type, prefer lower distance_ranking
        # on equal distance, prefer single hop
        return (
            - transfer_path[0].src.source_ranking + source_ranking_penalty,
            transfer_path[0].src.rse.is_tape_or_staging_required(),  # rely on the fact that False < True
            transfer_path[0].src.distance_ranking,
            len(transfer_path) > 1,  # rely on the fact that False < True
        )

    yield from sorted(candidate_paths, key=__transfer_order_key)


def build_transfer_paths(
        topology: "Topology",
        requests_with_sources: "Iterable[RequestWithSources]",
        admin_accounts: "Optional[Set[InternalAccount]]" = None,
        schemes: "Optional[List[str]]" = None,
        failover_schemes: "Optional[List[str]]" = None,
        transfertools: "Optional[List[str]]" = None,
        requested_source_only: bool = False,
        preparer_mode: bool = False,
        logger: "Callable" = logging.log,
        session: "Optional[Session]" = None,
):
    """
    For each request, find all possible transfer paths from its sources, which respect the
    constraints enforced by the request (attributes, type, etc) and the arguments of this function

    build a multi-source transfer if possible: The scheme compatibility is important for multi-source transfers.
    We iterate again over the single-hop sources and build a new transfer definition while enforcing the scheme compatibility
    with the initial source.

    Each path is a list of hops. Each hop is a transfer definition.
    """
    if schemes is None:
        schemes = []

    if failover_schemes is None:
        failover_schemes = []

    if admin_accounts is None:
        admin_accounts = set()

    protocol_factory = ProtocolFactory()

    # Do not print full source RSE list for DIDs which have many sources. Otherwise we fill the monitoring
    # storage with data which has little to no benefit. This log message is unlikely to help debugging
    # transfers issues when there are many sources, but can be very useful for small number of sources.
    num_sources_in_logs = 4

    candidate_paths_by_request_id, reqs_no_source, reqs_only_tape_source, reqs_scheme_mismatch = {}, set(), set(), set()
    reqs_unsupported_transfertool = set()
    for rws in requests_with_sources:

        rws.dest_rse = topology.rse_collection.setdefault(rws.dest_rse.id, rws.dest_rse)
        rws.dest_rse.ensure_loaded(load_name=True, load_info=True, load_attributes=True, session=session)

        all_sources = rws.sources
        for source in all_sources:
            source.rse = topology.rse_collection.setdefault(source.rse.id, source.rse)
            source.rse.ensure_loaded(load_name=True, load_info=True, load_attributes=True, session=session)

        transfer_schemes = schemes
        if rws.previous_attempt_id and failover_schemes:
            transfer_schemes = failover_schemes

        # Assume request doesn't have any sources. Will be removed later if sources are found.
        reqs_no_source.add(rws.request_id)
        if not all_sources:
            logger(logging.INFO, '%s: has no sources. Skipping.', rws)
            continue

        logger(logging.DEBUG, '%s: Working on %d sources%s: %s%s',
               rws,
               len(all_sources),
               f' (priority {rws.requested_source.rse})' if requested_source_only and rws.requested_source else '',
               ','.join('{}:{}:{}'.format(src.rse, src.source_ranking, src.distance_ranking) for src in all_sources[:num_sources_in_logs]),
               '... and %d others' % (len(all_sources) - num_sources_in_logs) if len(all_sources) > num_sources_in_logs else '')

        # Check if destination is blocked
        if rws.dest_rse.id in topology.unavailable_write_rses:
            logger(logging.WARNING, '%s: dst RSE is blocked for write. Will skip the submission of new jobs', rws.request_id)
            continue
        if rws.account not in admin_accounts and rws.dest_rse.id in topology.restricted_write_rses:
            logger(logging.WARNING, '%s: dst RSE is restricted for write. Will skip the submission', rws.request_id)
            continue

        if rws.transfertool and transfertools and rws.transfertool not in transfertools:
            # The request explicitly asks for a transfertool which this submitter doesn't support
            logger(logging.INFO, '%s: unsupported transfertool. Skipping.', rws.request_id)
            reqs_unsupported_transfertool.add(rws.request_id)
            reqs_no_source.remove(rws.request_id)
            continue

        # parse source expression
        source_replica_expression = rws.attributes.get('source_replica_expression', None)
        allowed_source_rses = None
        if source_replica_expression:
            try:
                parsed_rses = parse_expression(source_replica_expression, session=session)
            except InvalidRSEExpression as error:
                logger(logging.ERROR, "%s: Invalid RSE exception %s: %s", rws.request_id, source_replica_expression, str(error))
                continue
            else:
                allowed_source_rses = [x['id'] for x in parsed_rses]

        filtered_sources = all_sources
        # Only keep allowed sources
        if allowed_source_rses is not None:
            filtered_sources = filter(lambda s: s.rse.id in allowed_source_rses, filtered_sources)
        filtered_sources = filter(lambda s: s.rse.name is not None, filtered_sources)
        if rws.account not in admin_accounts:
            filtered_sources = filter(lambda s: s.rse.id not in topology.restricted_read_rses, filtered_sources)
        # Ignore blocklisted RSEs
        filtered_sources = filter(lambda s: s.rse.id not in topology.unavailable_read_rses, filtered_sources)
        # For staging requests, the staging_buffer attribute must be correctly set
        if rws.request_type == RequestType.STAGEIN:
            filtered_sources = filter(lambda s: s.rse.attributes.get('staging_buffer') == rws.dest_rse.name, filtered_sources)
        # Ignore tape sources if they are not desired
        filtered_sources = list(filtered_sources)
        had_tape_sources = len(filtered_sources) > 0
        if not rws.attributes.get("allow_tape_source", True):
            filtered_sources = filter(lambda s: not s.rse.is_tape_or_staging_required(), filtered_sources)

        filtered_sources = list(filtered_sources)
        filtered_rses_log = ''
        if len(all_sources) != len(filtered_sources):
            filtered_rses = list(set(s.rse.name for s in all_sources).difference(s.rse.name for s in filtered_sources))
            filtered_rses_log = '; %d dropped by filter: ' % (len(all_sources) - len(filtered_sources))
            filtered_rses_log += ','.join(filtered_rses[:num_sources_in_logs])
            if len(filtered_rses) > num_sources_in_logs:
                filtered_rses_log += '... and %d others' % (len(filtered_rses) - num_sources_in_logs)
        candidate_paths = []

        candidate_sources = filtered_sources
        if requested_source_only and rws.requested_source:
            candidate_sources = [rws.requested_source] if rws.requested_source in filtered_sources else []

        if rws.request_type == RequestType.STAGEIN:
            paths = __create_stagein_definitions(rws=rws,
                                                 sources=candidate_sources,
                                                 limit_dest_schemes=transfer_schemes,
                                                 operation_src='read',
                                                 operation_dest='write',
                                                 protocol_factory=protocol_factory)
        else:
            paths = __create_transfer_definitions(topology=topology,
                                                  rws=rws,
                                                  sources=candidate_sources,
                                                  multi_source_sources=[] if preparer_mode else filtered_sources,
                                                  limit_dest_schemes=[],
                                                  operation_src='third_party_copy_read',
                                                  operation_dest='third_party_copy_write',
                                                  domain='wan',
                                                  protocol_factory=protocol_factory,
                                                  session=session)

        sources_without_path = []
        any_source_had_scheme_mismatch = False
        for source in candidate_sources:
            transfer_path = paths.get(source.rse.id)
            if transfer_path is None:
                logger(logging.WARNING, "%s: no path from %s to %s", rws.request_id, source.rse, rws.dest_rse)
                sources_without_path.append(source.rse.name)
                continue
            if not transfer_path:
                any_source_had_scheme_mismatch = True
                logger(logging.WARNING, "%s: no matching protocol between %s and %s", rws.request_id, source.rse, rws.dest_rse)
                sources_without_path.append(source.rse.name)
                continue

            if len(transfer_path) > 1:
                logger(logging.DEBUG, '%s: From %s to %s requires multihop: %s', rws.request_id, source.rse, rws.dest_rse, transfer_path_str(transfer_path))

            candidate_paths.append(transfer_path)

        if len(candidate_sources) != len(candidate_paths):
            logger(logging.DEBUG, '%s: Sources after path computation: %s', rws.request_id, [str(path[0].src.rse) for path in candidate_paths])

        sources_without_path_log = ''
        if sources_without_path:
            sources_without_path_log = '; %d dropped due to missing path: ' % len(sources_without_path)
            sources_without_path_log += ','.join(sources_without_path[:num_sources_in_logs])
            if len(sources_without_path) > num_sources_in_logs:
                sources_without_path_log += '... and %d others' % (len(sources_without_path) - num_sources_in_logs)

        candidate_paths = __filter_multihops_with_intermediate_tape(candidate_paths)
        if not preparer_mode:
            candidate_paths = __compress_multihops(candidate_paths, all_sources)
        candidate_paths = list(__sort_paths(candidate_paths))

        ordered_sources_log = ','.join(('multihop: ' if len(path) > 1 else '') + '{}:{}:{}'.format(path[0].src.rse, path[0].src.source_ranking, path[0].src.distance_ranking)
                                       for path in candidate_paths[:num_sources_in_logs])
        if len(candidate_paths) > num_sources_in_logs:
            ordered_sources_log += '... and %d others' % (len(candidate_paths) - num_sources_in_logs)

        logger(logging.INFO, '%s: %d ordered sources: %s%s%s', rws, len(candidate_paths),
               ordered_sources_log, filtered_rses_log, sources_without_path_log)

        if not candidate_paths:
            # It can happen that some sources are skipped because they are TAPE, and others because
            # of scheme mismatch. However, we can only have one state in the database. I picked to
            # prioritize setting only_tape_source without any particular reason.
            if had_tape_sources and not filtered_sources:
                logger(logging.DEBUG, '%s: Only tape sources found' % rws.request_id)
                reqs_only_tape_source.add(rws.request_id)
                reqs_no_source.remove(rws.request_id)
            elif any_source_had_scheme_mismatch:
                logger(logging.DEBUG, '%s: Scheme mismatch detected' % rws.request_id)
                reqs_scheme_mismatch.add(rws.request_id)
                reqs_no_source.remove(rws.request_id)
            else:
                logger(logging.DEBUG, '%s: No candidate path found' % rws.request_id)
            continue

        candidate_paths_by_request_id[rws.request_id] = candidate_paths
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
def list_transfer_admin_accounts(session=None) -> "Set[InternalAccount]":
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


def cancel_transfer(transfertool_obj, transfer_id):
    """
    Cancel a transfer based on external transfer id.

    :param transfertool_obj: Transfertool object to be used for cancellation.
    :param transfer_id:      External-ID as a 32 character hex string.
    """

    record_counter('core.request.cancel_request_external_id')
    try:
        transfertool_obj.cancel(transfer_ids=[transfer_id])
    except Exception:
        raise RucioException('Could not cancel FTS3 transfer %s on %s: %s' % (transfer_id, transfertool_obj, traceback.format_exc()))


@transactional_session
def prepare_transfers(
        candidate_paths_by_request_id: "Dict[str, List[List[DirectTransferDefinition]]]",
        logger: "LoggerFunction" = logging.log,
        transfertools: "Optional[List[str]]" = None,
        session: "Optional[Session]" = None,
) -> "Tuple[List[str], List[str]]":
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

        update_dict = {
            models.Request.state: _throttler_request_state(
                activity=rws.activity,
                source_rse=selected_source.rse,
                dest_rse=rws.dest_rse,
                session=session,
            ),
            models.Request.source_rse_id: selected_source.rse.id,
        }
        if transfertool:
            update_dict[models.Request.transfertool] = transfertool

        stmt = update(
            models.Request
        ).where(
            models.Request.id == rws.request_id
        ).execution_options(
            synchronize_session=False
        ).values(
            update_dict
        )
        session.execute(stmt)
        updated_reqs.append(request_id)

    return updated_reqs, reqs_no_transfertool


def applicable_rse_transfer_limits(
        source_rse: "Optional[RseData]" = None,
        dest_rse: "Optional[RseData]" = None,
        activity: "Optional[str]" = None,
        session: "Optional[Session]" = None,
):
    """
    Find all RseTransferLimits which must be enforced for transfers between source and destination RSEs for the given activity.
    """
    source_limits = {}
    if source_rse:
        source_limits = source_rse.ensure_loaded(load_transfer_limits=True, session=session).transfer_limits.get('source', {})
    dest_limits = {}
    if dest_rse:
        dest_limits = dest_rse.ensure_loaded(load_transfer_limits=True, session=session).transfer_limits.get('destination', {})

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


def _throttler_request_state(activity, source_rse, dest_rse, session: "Optional[Session]" = None) -> RequestState:
    """
    Takes request attributes to return a new state for the request
    based on throttler settings. Always returns QUEUED,
    if the throttler mode is not set.
    """
    limit_found = False
    if any(applicable_rse_transfer_limits(activity=activity, source_rse=source_rse, dest_rse=dest_rse, session=session)):
        limit_found = True

    return RequestState.WAITING if limit_found else RequestState.QUEUED


def get_supported_transfertools(
        source_rse: "RseData",
        dest_rse: "RseData",
        transfertools: "Optional[List[str]]" = None,
        session: "Optional[Session]" = None,
) -> "Set[str]":

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
