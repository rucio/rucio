# -*- coding: utf-8 -*-
# Copyright 2013-2022 CERN
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
#
# Authors:
# - Mario Lassnig <mario.lassnig@cern.ch>, 2013-2021
# - Martin Barisits <martin.barisits@cern.ch>, 2017-2022
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017
# - Igor Mandrichenko <rucio@fermicloud055.fnal.gov>, 2018
# - Cedric Serfon <cedric.serfon@cern.ch>, 2018-2021
# - dciangot <diego.ciangottini@cern.ch>, 2018
# - Robert Illingworth <illingwo@fnal.gov>, 2018-2019
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Matt Snyder <msnyder@bnl.gov>, 2019-2021
# - Gabriele Fronze' <gfronze@cern.ch>, 2019
# - Jaroslav Guenther <jaroslav.guenther@cern.ch>, 2019-2020
# - Eric Vaandering <ewv@fnal.gov>, 2020
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Nick Smith <nick.smith@cern.ch>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Thomas Beermann <thomas.beermann@cern.ch>, 2021
# - Rahul Chauhan <omrahulchauhan@gmail.com>, 2021
# - Radu Carpa <radu.carpa@cern.ch>, 2021-2022
# - Sahan Dilshan <32576163+sahandilshan@users.noreply.github.com>, 2021
# - Petr Vokac <petr.vokac@fjfi.cvut.cz>, 2021
# - David Población Criado <david.poblacion.criado@cern.ch>, 2021

from __future__ import division

import copy
import datetime
import json
import logging
import re
import time
from rucio.common.utils import PriorityQueue
from typing import TYPE_CHECKING

from dogpile.cache.api import NoValue
from sqlalchemy import and_, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql.expression import false

from rucio.common import constants
from rucio.common.cache import make_region_memcached
from rucio.common.config import config_get, config_get_bool
from rucio.common.constants import SUPPORTED_PROTOCOLS, FTS_STATE
from rucio.common.exception import (InvalidRSEExpression, NoDistance,
                                    RequestNotFound, RSEProtocolNotSupported,
                                    RucioException, UnsupportedOperation)
from rucio.common.extra import import_extras
from rucio.common.rse_attributes import get_rse_attributes
from rucio.common.utils import construct_surl
from rucio.core import did, message as message_core, request as request_core
from rucio.core.config import get as core_config_get
from rucio.core.monitor import record_counter, record_timer
from rucio.core.replica import add_replicas, tombstone_from_delay, update_replica_state
from rucio.core.request import get_request_by_did, queue_requests, set_request_state
from rucio.core.rse import get_rse_name, get_rse_vo, list_rses
from rucio.core.rse_expression_parser import parse_expression
from rucio.db.sqla import models, filter_thread_work
from rucio.db.sqla.constants import DIDType, RequestState, RSEType, RequestType, ReplicaState
from rucio.db.sqla.session import read_session, transactional_session
from rucio.db.sqla.util import create_temp_table
from rucio.rse import rsemanager as rsemgr
from rucio.transfertool.transfertool import Transfertool, TransferToolBuilder
from rucio.transfertool.fts3 import FTS3Transfertool

if TYPE_CHECKING:
    from typing import Any, Callable, Dict, Generator, Iterable, List, Optional, Set, Tuple, Type, Union
    from sqlalchemy.orm import Session

EXTRA_MODULES = import_extras(['globus_sdk'])

if EXTRA_MODULES['globus_sdk']:
    from rucio.transfertool.globus import GlobusTransferTool  # pylint: disable=import-error


"""
The core transfer.py is specifically for handling transfer-requests, thus requests
where the external_id is already known.
Requests accessed by request_id  are covered in the core request.py
"""

REGION_SHORT = make_region_memcached(expiration_time=600)

WEBDAV_TRANSFER_MODE = config_get('conveyor', 'webdav_transfer_mode', False, None)

DEFAULT_MULTIHOP_TOMBSTONE_DELAY = int(datetime.timedelta(hours=2).total_seconds())

# For how much time to skip handling a request when a concurrent submission by multiple submitters is suspected
CONCURRENT_SUBMISSION_TOLERATION_DELAY = datetime.timedelta(minutes=5)


class RseData:
    """
    Helper data class storing rse data grouped in one place.
    """
    def __init__(self, id_, name=None, attributes=None, info=None):
        self.id = id_
        self.name = name
        self.attributes = attributes
        self.info = info

    def __str__(self):
        if self.name is not None:
            return self.name
        return self.id

    def __eq__(self, other):
        if other is None:
            return False
        return self.id == other.id

    def is_tape(self):
        if self.info['rse_type'] == RSEType.TAPE or self.info['rse_type'] == 'TAPE':
            return True
        return False

    def is_tape_or_staging_required(self):
        if self.is_tape() or self.attributes.get('staging_required', False):
            return True
        return False

    @read_session
    def load_name(self, session=None):
        if self.name is None:
            self.name = get_rse_name(rse_id=self.id, session=session)
        return self.name

    @read_session
    def load_attributes(self, session=None):
        if self.attributes is None:
            self.attributes = get_rse_attributes(self.id, session=session)
        return self.attributes

    @read_session
    def load_info(self, session=None):
        if self.info is None:
            self.info = rsemgr.get_rse_info(rse=self.load_name(session=session),
                                            vo=get_rse_vo(rse_id=self.id, session=session),
                                            session=session)
        return self.info


class TransferSource:
    def __init__(self, rse_data, source_ranking=None, distance_ranking=None, file_path=None, scheme=None, url=None):
        self.rse = rse_data
        self.distance_ranking = distance_ranking if distance_ranking is not None else 9999
        self.source_ranking = source_ranking if source_ranking is not None else 0
        self.file_path = file_path
        self.scheme = scheme
        self.url = url

    def __str__(self):
        return "src_rse={}".format(self.rse)


class TransferDestination:
    def __init__(self, rse_data, scheme):
        self.rse = rse_data
        self.scheme = scheme

    def __str__(self):
        return "dst_rse={}".format(self.rse)


class RequestWithSources:
    def __init__(self, id_, request_type, rule_id, scope, name, md5, adler32, byte_count, activity, attributes,
                 previous_attempt_id, dest_rse_data, account, retry_count, priority, transfertool, requested_at=None):

        self.request_id = id_
        self.request_type = request_type
        self.rule_id = rule_id
        self.scope = scope
        self.name = name
        self.md5 = md5
        self.adler32 = adler32
        self.byte_count = byte_count
        self.activity = activity
        self._dict_attributes = None
        self._db_attributes = attributes
        self.previous_attempt_id = previous_attempt_id
        self.dest_rse = dest_rse_data
        self.account = account
        self.retry_count = retry_count or 0
        self.priority = priority if priority is not None else 3
        self.transfertool = transfertool
        self.requested_at = requested_at if requested_at else datetime.datetime.utcnow()

        self.sources = []

    def __str__(self):
        return "{}({}:{})".format(self.request_id, self.scope, self.name)

    @property
    def attributes(self):
        if self._dict_attributes is None:
            self.attributes = self._db_attributes
        return self._dict_attributes

    @attributes.setter
    def attributes(self, db_attributes):
        attr = {}
        if db_attributes:
            if isinstance(db_attributes, dict):
                attr = json.loads(json.dumps(db_attributes))
            else:
                attr = json.loads(str(db_attributes))
            # parse source expression
            attr['source_replica_expression'] = attr["source_replica_expression"] if (attr and "source_replica_expression" in attr) else None
            attr['allow_tape_source'] = attr["allow_tape_source"] if (attr and "allow_tape_source" in attr) else True
            attr['dsn'] = attr["ds_name"] if (attr and "ds_name" in attr) else None
            attr['lifetime'] = attr.get('lifetime', -1)
        self._dict_attributes = attr


class _RseLoaderContext:
    """
    Helper private class used to dynamically load and cache the rse information
    """
    def __init__(self, session):
        self.session = session
        self.rse_id_to_data_map = {}

    def rse_data(self, rse_id):
        rse_data = self.rse_id_to_data_map.get(rse_id)
        if rse_data is None:
            rse_data = RseData(rse_id)
            rse_data.load_name(session=self.session)
            rse_data.load_info(session=self.session)
            rse_data.load_attributes(session=self.session)
            self.rse_id_to_data_map[rse_id] = rse_data
        return rse_data

    def ensure_fully_loaded(self, rse_data):
        if rse_data.name is None or rse_data.info is None or rse_data.attributes is None:
            cached_rse_data = self.rse_data(rse_data.id)
            if rse_data.name is None:
                rse_data.name = cached_rse_data.name
            if rse_data.info is None:
                rse_data.info = cached_rse_data.info
            if rse_data.attributes is None:
                rse_data.attributes = cached_rse_data.attributes


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
    def __init__(self, source: TransferSource, destination: TransferDestination, rws: RequestWithSources,
                 protocol_factory: ProtocolFactory, operation_src: str, operation_dest: str):
        self.sources = [source]
        self.destination = destination

        self.rws = rws
        self.protocol_factory = protocol_factory
        self.operation_src = operation_src
        self.operation_dest = operation_dest

        self.dict_attributes = {}

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

    def __setitem__(self, key, value):
        self.dict_attributes[key] = value

    def __getitem__(self, key):
        return self.dict_attributes[key]

    def get(self, key, default=None):
        return self.dict_attributes.get(key, default)

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
    def _generate_source_url(cls, src: TransferSource, dst: TransferDestination, rws: RequestWithSources, protocol_factory: ProtocolFactory, operation: str):
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
            dest_path = construct_surl(dsn, rws.name, naming_convention)
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

    if len(transfer_path) == 1:
        return str(transfer_path[0])

    path_str = str(transfer_path[0].src.rse)
    for hop in transfer_path:
        path_str += '--{request_id}->{destination}'.format(request_id=hop.rws.request_id or '', destination=hop.dst.rse)
    return path_str


@transactional_session
def mark_submitting_and_prepare_sources_for_transfer(
        transfer: "DirectTransferDefinition",
        external_host: str,
        logger: "Callable",
        session: "Optional[Session]" = None,
):
    """
    Prepare the sources for transfers.
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
    logger(logging.INFO, "%s", log_str)

    rowcount = session.query(models.Request)\
                      .filter_by(id=transfer.rws.request_id)\
                      .filter(models.Request.state == RequestState.QUEUED)\
                      .update({'state': RequestState.SUBMITTING,
                               'external_id': None,
                               'external_host': external_host,
                               'dest_url': transfer.dest_url,
                               'submitted_at': datetime.datetime.utcnow()},
                              synchronize_session=False)
    if rowcount == 0:
        raise RequestNotFound("Failed to prepare transfer: request %s does not exist or is not in queued state" % transfer.rws)

    for src_rse, src_url, src_rse_id, rank in transfer.legacy_sources:
        # For multi-hops, sources in database are bound to the initial request
        source_request_id = transfer.rws.attributes.get('initial_request_id', transfer.rws.request_id)
        src_rowcount = session.query(models.Source)\
                              .filter_by(request_id=source_request_id)\
                              .filter(models.Source.rse_id == src_rse_id)\
                              .update({'is_using': True}, synchronize_session=False)
        if src_rowcount == 0:
            models.Source(request_id=source_request_id,
                          scope=transfer.rws.scope,
                          name=transfer.rws.name,
                          rse_id=src_rse_id,
                          dest_rse_id=transfer.dst.rse.id,
                          ranking=rank if rank else 0,
                          bytes=transfer.rws.byte_count,
                          url=src_url,
                          is_using=True).\
                save(session=session, flush=False)


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
            rowcount = session.query(models.Request)\
                              .filter_by(id=transfer.rws.request_id)\
                              .filter(models.Request.state == RequestState.SUBMITTING)\
                              .update({'state': state,
                                       'external_id': external_id,
                                       'external_host': external_host,
                                       'source_rse_id': transfer.src.rse.id,
                                       'submitted_at': submitted_at},
                                      synchronize_session=False)

            if rowcount == 0:
                raise RucioException("Failed to set requests %s tansfer %s: request doesn't exist or is not in SUBMITTING state" % rws)

            msg = {'request-id': rws.request_id,
                   'request-type': rws.request_type,
                   'scope': rws.scope.external,
                   'name': rws.name,
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
                   'queued_at': str(submitted_at)}
            if rws.scope.vo != 'def':
                msg['vo'] = rws.scope.vo

            if msg['request-type']:
                transfer_status = '%s-%s' % (msg['request-type'].name, msg['state'].name)
            else:
                transfer_status = 'transfer-%s' % msg['state']
            transfer_status = transfer_status.lower()

            message_core.add_message(transfer_status, msg, session=session)

    except IntegrityError as error:
        raise RucioException(error.args)

    logger(logging.DEBUG, 'Finished to register transfer state for %s' % external_id)


def is_recoverable_fts_overwrite_error(fts_status_dict):
    """
    Verify the special case when FTS cannot copy a file because destination exists and overwrite is disabled,
    but the destination file is actually correct.

    This can happen when some transitory error happened during a previous submission attempt.
    Hence, the transfer is correctly executed by FTS, but rucio doesn't know about it.

    Returns true when the request must be marked as successful even if it was reported failed by FTS.
    """
    if 'Destination file exists and overwrite is not enabled' in (fts_status_dict.get('reason') or ''):
        dst_file = fts_status_dict['dst_file']
        request_id = fts_status_dict['request_id']
        request = None
        if request_id:
            request = request_core.get_request(request_id)
        if (request and dst_file
                and dst_file.get('file_size')
                and dst_file.get('file_size') == request.get('bytes')
                and (dst_file.get('checksum_type', '').lower() == 'adler32' and dst_file.get('checksum_value') == request.get('adler32')
                     or dst_file.get('checksum_type', '').lower() == 'md5' and dst_file.get('checksum_value') == request.get('md5'))):
            if dst_file.get('file_on_tape'):
                return True
            elif fts_status_dict.get('dst_type') == 'DISK':
                return True
    return False


def bulk_query_transfers(request_host, transfers_by_eid, transfertool='fts3', vo=None, timeout=None, logger=logging.log):
    """
    Query the status of a transfer.
    :param request_host:     Name of the external host.
    :param transfers_by_eid: Dict of the form {external_id: list_of_transfers}
    :param transfertool:     Transfertool name as a string.
    :param timeout:          Transfertool timeout.
    :param logger:           Optional decorated logger that can be passed from the calling daemons or servers.
    :returns:                Request status information as a dictionary.
    """

    record_counter('core.request.bulk_query_transfers')

    if transfertool == 'fts3':
        start_time = time.time()
        fts_resps = FTS3Transfertool(external_host=request_host, vo=vo).bulk_query(transfer_ids=list(transfers_by_eid), timeout=timeout)
        record_timer('core.request.bulk_query_transfers_fts3', (time.time() - start_time) * 1000 / len(transfers_by_eid))

        for external_id, transfers in transfers_by_eid.items():
            if external_id not in fts_resps:
                fts_resps[external_id] = Exception("Transfer id %s is not returned" % external_id)
            if fts_resps[external_id] and not isinstance(fts_resps[external_id], Exception):
                for request_id in fts_resps[external_id]:
                    status_dict = fts_resps[external_id][request_id]
                    job_state = status_dict['job_state']
                    file_state = status_dict['file_state']
                    # https://fts3-docs.web.cern.ch/fts3-docs/docs/state_machine.html
                    job_state_is_final = job_state in (FTS_STATE.FAILED, FTS_STATE.CANCELED, FTS_STATE.FINISHED, FTS_STATE.FINISHEDDIRTY)
                    file_state_is_final = file_state in (FTS_STATE.FAILED, FTS_STATE.CANCELED, FTS_STATE.FINISHED, FTS_STATE.NOT_USED)
                    if not file_state_is_final:
                        continue

                    if file_state == FTS_STATE.FINISHED:
                        status_dict['new_state'] = RequestState.DONE
                    elif job_state_is_final and file_state == FTS_STATE.FAILED and is_recoverable_fts_overwrite_error(status_dict):
                        status_dict['new_state'] = RequestState.DONE
                    elif job_state_is_final and file_state in (FTS_STATE.FAILED, FTS_STATE.CANCELED):
                        status_dict['new_state'] = RequestState.FAILED
                    elif job_state_is_final and file_state == FTS_STATE.NOT_USED:
                        if job_state == FTS_STATE.FINISHED:
                            # it is a multi-source transfer. This source wasn't used, but another one was successful
                            status_dict['new_state'] = RequestState.DONE
                        else:
                            # failed multi-source or multi-hop (you cannot have unused sources in a successful multi-hop)
                            status_dict['new_state'] = RequestState.FAILED
        return fts_resps
    elif transfertool == 'globus':
        start_time = time.time()
        logger(logging.DEBUG, 'transfer_ids: %s' % list(transfers_by_eid))
        responses = GlobusTransferTool(external_host=None).bulk_query(transfer_ids=list(transfers_by_eid), timeout=timeout)
        record_timer('core.request.bulk_query_transfers', (time.time() - start_time) * 1000 / len(transfers_by_eid))

        for k, v in responses.items():
            if v == 'FAILED':
                new_state = RequestState.FAILED
            elif v == 'SUCCEEDED':
                new_state = RequestState.DONE
            else:
                new_state = RequestState.SUBMITTED
            responses[k] = {t['request_id']: fake_transfertool_response(t, new_state=new_state)
                            for t in transfers_by_eid[k]}
        return responses
    else:
        raise NotImplementedError


@transactional_session
def fake_transfertool_response(req, new_state=None, reason=None, session=None):
    """
    Use the request database object to return a dict in the same format as
    returned by the FTS transfertool. Fill ass many fields as possible with
    relevant data.

    TODO: get rid of this function
    """
    src_rse_id = req.get('source_rse_id', None)
    dst_rse_id = req.get('dest_rse_id', None)
    src_rse = None
    dst_rse = None
    if src_rse_id:
        src_rse = get_rse_name(src_rse_id, session=session)
    if dst_rse_id:
        dst_rse = get_rse_name(dst_rse_id, session=session)
    response = {'new_state': new_state or req.get('state', None),
                'transfer_id': req['external_id'],
                'job_state': new_state or req.get('state', None),
                'src_url': None,
                'dst_url': req['dest_url'],
                'duration': 0,
                'reason': reason,
                'scope': req.get('scope', None),
                'name': req.get('name', None),
                'src_rse': src_rse,
                'dst_rse': dst_rse,
                'request_id': req.get('request_id', None),
                'activity': req.get('activity', None),
                'src_rse_id': req.get('source_rse_id', None),
                'dst_rse_id': req.get('dest_rse_id', None),
                'previous_attempt_id': req.get('previous_attempt_id', None),
                'adler32': req.get('adler32', None),
                'md5': req.get('md5', None),
                'filesize': req.get('filesize', None),
                'external_host': req.get('external_host', None),
                'job_m_replica': None,
                'created_at': req.get('created_at', None),
                'submitted_at': req.get('submitted_at', None),
                'details': None,
                'account': req.get('account', None)}
    return response


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
        rowcount = session.query(models.Request).filter_by(external_id=transfer_id, state=RequestState.SUBMITTED).update({'updated_at': update_time}, synchronize_session=False)
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
        stmt = update(models.Request).prefix_with("/*+ INDEX(REQUESTS REQUESTS_EXTERNALID_UQ) */", dialect='oracle')\
                                     .filter_by(external_id=transfer_id)\
                                     .where(models.Request.state == RequestState.SUBMITTED)\
                                     .where(models.Request.updated_at < datetime.datetime.utcnow() - datetime.timedelta(seconds=30))\
                                     .execution_options(synchronize_session=False)\
                                     .values(updated_at=datetime.datetime.utcnow())
        session.execute(stmt)
    except IntegrityError as error:
        raise RucioException(error.args)


@transactional_session
def get_hops(source_rse_id, dest_rse_id, multihop_rses=None, limit_dest_schemes=None, session=None):
    """
    Get a list of hops needed to transfer date from source_rse_id to dest_rse_id.
    Ideally, the list will only include one item (dest_rse_id) since no hops are needed.
    :param source_rse_id:       Source RSE id of the transfer.
    :param dest_rse_id:         Dest RSE id of the transfer.
    :param multihop_rses:       List of RSE ids that can be used for multihop. If empty, multihop is disabled.
    :param limit_dest_schemes:  List of destination schemes the matching scheme algorithm should be limited to for a single hop.
    :returns:                   List of hops in the format [{'source_rse_id': source_rse_id, 'source_scheme': 'srm', 'source_scheme_priority': N, 'dest_rse_id': dest_rse_id, 'dest_scheme': 'srm', 'dest_scheme_priority': N}]
    :raises:                    NoDistance
    """
    if not limit_dest_schemes:
        limit_dest_schemes = []

    if not multihop_rses:
        multihop_rses = []

    shortest_paths = __search_shortest_paths(source_rse_ids=[source_rse_id], dest_rse_id=dest_rse_id,
                                             operation_src='third_party_copy', operation_dest='third_party_copy',
                                             domain='wan', multihop_rses=multihop_rses,
                                             limit_dest_schemes=limit_dest_schemes, session=session)

    result = REGION_SHORT.get('get_hops_dist_%s_%s_%s' % (str(source_rse_id), str(dest_rse_id), ''.join(sorted(limit_dest_schemes))))
    if not isinstance(result, NoValue):
        return result

    path = shortest_paths.get(source_rse_id)
    if path is None:
        raise NoDistance()

    if not path:
        raise RSEProtocolNotSupported()

    REGION_SHORT.set('get_hops_dist_%s_%s_%s' % (str(source_rse_id), str(dest_rse_id), ''.join(sorted(limit_dest_schemes))), path)
    return path


def __search_shortest_paths(
        source_rse_ids: "List[str]",
        dest_rse_id: "List[str]",
        operation_src: str,
        operation_dest: str,
        domain: str,
        multihop_rses: "List[str]",
        limit_dest_schemes: "Union[str, List[str]]",
        inbound_links_by_node: "Optional[Dict[str, Dict[str, str]]]" = None,
        session: "Optional[Session]" = None,
) -> "Dict[str, List[Dict[str, Any]]]":
    """
    Find the shortest paths from multiple sources towards dest_rse_id.
    Does a Backwards Dijkstra's algorithm: start from destination and follow inbound links towards the sources.
    If multihop is disabled, stop after analysing direct connections to dest_rse. Otherwise, stops when all
    sources where found or the graph was traversed in integrality.

    The inbound links retrieved from the database can be accumulated into the inbound_links_by_node, passed
    from the calling context. To be able to reuse them.
    """
    HOP_PENALTY = config_get('transfers', 'hop_penalty', default=10, session=session)  # Penalty to be applied to each further hop

    if multihop_rses:
        # Filter out island source RSEs
        sources_to_find = {rse_id for rse_id in source_rse_ids if __load_outgoing_distances_node(rse_id=rse_id, session=session)}
    else:
        sources_to_find = set(source_rse_ids)

    next_hop = {dest_rse_id: {'cumulated_distance': 0}}
    priority_q = PriorityQueue()

    remaining_sources = copy.copy(sources_to_find)
    priority_q[dest_rse_id] = 0
    while priority_q:
        current_node = priority_q.pop()

        if current_node in remaining_sources:
            remaining_sources.remove(current_node)
        if not remaining_sources:
            # We found the shortest paths to all desired sources
            break

        current_distance = next_hop[current_node]['cumulated_distance']
        inbound_links = __load_inbound_distances_node(rse_id=current_node, session=session)
        if inbound_links_by_node is not None:
            inbound_links_by_node[current_node] = inbound_links
        for adjacent_node, link_distance in sorted(inbound_links.items(),
                                                   key=lambda item: 0 if item[0] in sources_to_find else 1):
            if link_distance is None:
                continue

            if adjacent_node not in remaining_sources and adjacent_node not in multihop_rses:
                continue

            new_adjacent_distance = current_distance + link_distance + HOP_PENALTY
            if next_hop.get(adjacent_node, {}).get('cumulated_distance', 9999) <= new_adjacent_distance:
                continue

            try:
                matching_scheme = rsemgr.find_matching_scheme(
                    rse_settings_src=__load_rse_settings(rse_id=adjacent_node, session=session),
                    rse_settings_dest=__load_rse_settings(rse_id=current_node, session=session),
                    operation_src=operation_src,
                    operation_dest=operation_dest,
                    domain=domain,
                    scheme=limit_dest_schemes if adjacent_node == dest_rse_id and limit_dest_schemes else None
                )
                next_hop[adjacent_node] = {
                    'source_rse_id': adjacent_node,
                    'dest_rse_id': current_node,
                    'source_scheme': matching_scheme[1],
                    'dest_scheme': matching_scheme[0],
                    'source_scheme_priority': matching_scheme[3],
                    'dest_scheme_priority': matching_scheme[2],
                    'hop_distance': link_distance,
                    'cumulated_distance': new_adjacent_distance,
                }
                priority_q[adjacent_node] = new_adjacent_distance
            except RSEProtocolNotSupported:
                if next_hop.get(adjacent_node) is None:
                    next_hop[adjacent_node] = {}

        if not multihop_rses:
            # Stop after the first iteration, which finds direct connections to destination
            break

    paths = {}
    for rse_id in source_rse_ids:
        hop = next_hop.get(rse_id)
        if hop is None:
            continue

        path = []
        while hop.get('dest_rse_id'):
            path.append(hop)
            hop = next_hop.get(hop['dest_rse_id'])
        paths[rse_id] = path
    return paths


@read_session
def __create_transfer_definitions(
        ctx: _RseLoaderContext,
        protocol_factory: ProtocolFactory,
        rws: RequestWithSources,
        sources: "List[TransferSource]",
        multihop_rses: "List[str]",
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
    shortest_paths = __search_shortest_paths(source_rse_ids=[s.rse.id for s in sources], dest_rse_id=rws.dest_rse.id,
                                             operation_src=operation_src, operation_dest=operation_dest, domain=domain,
                                             multihop_rses=multihop_rses, limit_dest_schemes=limit_dest_schemes,
                                             inbound_links_by_node=inbound_links_by_node, session=session)

    transfers_by_source = {}
    sources_by_rse_id = {s.rse.id: s for s in sources}
    paths_by_source = {sources_by_rse_id[rse_id]: path for rse_id, path in shortest_paths.items()}
    for source, list_hops in paths_by_source.items():
        transfer_path = []
        for hop in list_hops:
            hop_src_rse = ctx.rse_data(hop['source_rse_id'])
            hop_dst_rse = ctx.rse_data(hop['dest_rse_id'])
            src = TransferSource(
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
            for source in sorted(sources, key=lambda s: (-s.source_ranking, s.distance_ranking)):
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
                    TransferSource(
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
        sources: "List[TransferSource]",
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
                source=TransferSource(
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
        sources: "Iterable[TransferSource]",
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


def __handle_intermediate_hop_requests(
        requests_with_sources: "Iterable[RequestWithSources]",
        logger: "Callable" = logging.log,
) -> "Generator[RequestWithSources]":
    """
    Intermediate request of a multihop shouldn't stay in the QUEUED state for too long.
    They should be transited to SUBMITTED state by the submitter who created them
    almost immediately after creation.

    Due to the distributed nature of rucio, the short time window can be enough for
    this intermediate request to be picked by another submitter which will start
    working on it. This function takes care that this "other" submitter doesn't try
    to submit this intermediate request. It is also responsible to cleanup such
    intermediate requests which stays in a queued state for "too long". This probably
    means that the initial submitter, who created them, crashed before submission.
    """
    now = datetime.datetime.utcnow()
    for rws in requests_with_sources:
        if rws.attributes.get('initial_request_id'):
            # This is an intermediate hop, don't consider it for submission
            if rws.requested_at < now - CONCURRENT_SUBMISSION_TOLERATION_DELAY:
                logger(logging.WARNING, '%s: marking stalled intermediate hop as submission_failed', rws.request_id)
                set_request_state(request_id=rws.request_id, new_state=RequestState.SUBMISSION_FAILED)
            else:
                logger(logging.WARNING, '%s: skipping intermediate hop from being submitted on its own', rws.request_id)
        else:
            yield rws


@transactional_session
def next_transfers_to_submit(total_workers=0, worker_number=0, partition_hash_var=None, limit=None, activity=None, older_than=None, rses=None, schemes=None,
                             failover_schemes=None, filter_transfertool=None, transfertools_by_name=None, request_type=RequestType.TRANSFER,
                             ignore_availability=False, logger=logging.log, session=None):
    """
    Get next transfers to be submitted; grouped by transfertool which can submit them
    :param total_workers:         Number of total workers.
    :param worker_number:         Id of the executing worker.
    :param partition_hash_var     The hash variable used for partitioning thread work
    :param limit:                 Maximum number of requests to retrieve from database.
    :param activity:              Activity.
    :param older_than:            Get transfers older than.
    :param rses:                  Include RSES.
    :param schemes:               Include schemes.
    :param failover_schemes:      Failover schemes.
    :param transfertools_by_name: Dict: {transfertool_name_str: transfertool class}
    :param filter_transfertool:   The transfer tool to filter requests on.
    :param request_type           The type of requests to retrieve (Transfer/Stagein)
    :param ignore_availability:   Ignore blocklisted RSEs
    :param logger:                Optional decorated logger that can be passed from the calling daemons or servers.
    :param session:               The database session in use.
    :returns:                     Dict: {TransferToolBuilder: <list of transfer paths (possibly multihop) to be submitted>}

    Workflow:
    """

    include_multihop = False
    if filter_transfertool in ['fts3', None]:
        include_multihop = core_config_get('transfers', 'use_multihop', default=False, expiration_time=600, session=session)

    multihop_rses = []
    if include_multihop:
        try:
            multihop_rses = [rse['id'] for rse in parse_expression('available_for_multihop=true')]
        except InvalidRSEExpression:
            pass

    if schemes is None:
        schemes = []

    if failover_schemes is None:
        failover_schemes = []

    # retrieve (from the database) the transfer requests with their possible source replicas
    request_with_sources = __list_transfer_requests_and_source_replicas(
        total_workers=total_workers,
        worker_number=worker_number,
        partition_hash_var=partition_hash_var,
        limit=limit,
        activity=activity,
        older_than=older_than,
        rses=rses,
        request_type=request_type,
        request_state=RequestState.QUEUED,
        ignore_availability=ignore_availability,
        transfertool=filter_transfertool,
        session=session,
    )

    # Filter (and maybe mark as failed) intermediate hop requests
    request_with_sources = list(__handle_intermediate_hop_requests(request_with_sources, logger))

    # for each source, compute the (possibly multihop) path between it and the transfer destination
    candidate_paths, reqs_no_source, reqs_scheme_mismatch, reqs_only_tape_source = __build_transfer_paths(
        request_with_sources,
        multihop_rses=multihop_rses,
        schemes=schemes,
        failover_schemes=failover_schemes,
        ignore_availability=ignore_availability,
        logger=logger,
        session=session,
    )

    # Assign paths to be executed by transfertools
    # if the chosen best path is a multihop, create intermediate replicas and the intermediate transfer requests
    paths_by_transfertool_builder, reqs_no_host, reqs_unsupported_transfertool = __assign_paths_to_transfertool_and_create_hops(
        candidate_paths,
        transfertools_by_name=transfertools_by_name,
        logger=logger,
        session=session,
    )

    if reqs_unsupported_transfertool:
        logger(logging.INFO, "Ignoring request because of unsupported transfertool: %s", reqs_unsupported_transfertool)
    reqs_no_source.update(reqs_no_host)
    if reqs_no_source:
        logger(logging.INFO, "Marking requests as no-sources: %s", reqs_no_source)
        request_core.set_requests_state_if_possible(reqs_no_source, RequestState.NO_SOURCES, logger=logger, session=session)
    if reqs_only_tape_source:
        logger(logging.INFO, "Marking requests as only-tape-sources: %s", reqs_only_tape_source)
        request_core.set_requests_state_if_possible(reqs_only_tape_source, RequestState.ONLY_TAPE_SOURCES, logger=logger, session=session)
    if reqs_scheme_mismatch:
        logger(logging.INFO, "Marking requests as scheme-mismatch: %s", reqs_scheme_mismatch)
        request_core.set_requests_state_if_possible(reqs_scheme_mismatch, RequestState.MISMATCH_SCHEME, logger=logger, session=session)

    return paths_by_transfertool_builder


def __build_transfer_paths(
        requests_with_sources: "Iterable[RequestWithSources]",
        multihop_rses: "List[str]",
        schemes: "List[str]",
        failover_schemes: "List[str]",
        ignore_availability: bool = False,
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
    ctx = _RseLoaderContext(session)
    protocol_factory = ProtocolFactory()
    unavailable_read_rse_ids = __get_unavailable_rse_ids(operation='read', session=session)
    unavailable_write_rse_ids = __get_unavailable_rse_ids(operation='write', session=session)

    # Do not print full source RSE list for DIDs which have many sources. Otherwise we fill the monitoring
    # storage with data which has little to no benefit. This log message is unlikely to help debugging
    # transfers issues when there are many sources, but can be very useful for small number of sources.
    num_sources_in_logs = 4

    # Disallow multihop via blocklisted RSEs
    if not ignore_availability:
        multihop_rses = list(set(multihop_rses).difference(unavailable_write_rse_ids).difference(unavailable_read_rse_ids))

    candidate_paths_by_request_id, reqs_no_source, reqs_only_tape_source, reqs_scheme_mismatch = {}, set(), set(), set()
    for rws in requests_with_sources:

        ctx.ensure_fully_loaded(rws.dest_rse)
        for source in rws.sources:
            ctx.ensure_fully_loaded(source.rse)

        transfer_schemes = schemes
        if rws.previous_attempt_id and failover_schemes:
            transfer_schemes = failover_schemes

        logger(logging.INFO, '%s: Found %d sources', rws, len(rws.sources))

        # Assume request doesn't have any sources. Will be removed later if sources are found.
        reqs_no_source.add(rws.request_id)
        if not rws.sources:
            continue

        # Check if destination is blocked
        if not ignore_availability and rws.dest_rse.id in unavailable_write_rse_ids:
            logger(logging.WARNING, '%s: dst RSE is blocked for write. Will skip the submission of new jobs', rws.request_id)
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

        filtered_sources = rws.sources
        # Only keep allowed sources
        if allowed_source_rses is not None:
            filtered_sources = filter(lambda s: s.rse.id in allowed_source_rses, filtered_sources)
        filtered_sources = filter(lambda s: s.rse.name is not None, filtered_sources)
        # Ignore blocklisted RSEs
        if not ignore_availability:
            filtered_sources = filter(lambda s: s.rse.id not in unavailable_read_rse_ids, filtered_sources)
        # For staging requests, the staging_buffer attribute must be correctly set
        if rws.request_type == RequestType.STAGEIN:
            filtered_sources = filter(lambda s: s.rse.attributes.get('staging_buffer') == rws.dest_rse.name, filtered_sources)
        # Ignore tape sources if they are not desired
        filtered_sources = list(filtered_sources)
        had_tape_sources = len(filtered_sources) > 0
        if not rws.attributes.get("allow_tape_source", True):
            filtered_sources = filter(lambda s: not s.rse.is_tape_or_staging_required(), filtered_sources)

        filtered_sources = list(filtered_sources)
        if len(rws.sources) != len(filtered_sources):
            dropped_rses = list(set(s.rse.name for s in rws.sources).difference(s.rse.name for s in filtered_sources))
            dropped_rses_log = ','.join(dropped_rses[:num_sources_in_logs])
            if len(dropped_rses) > num_sources_in_logs:
                dropped_rses_log += '... and %d others' % (len(dropped_rses) - num_sources_in_logs)
            logger(logging.INFO, '%s: %d/%d sources left after filtering. Dropped: %s', rws.request_id, len(filtered_sources), len(rws.sources), dropped_rses_log)
        any_source_had_scheme_mismatch = False
        candidate_paths = []

        if rws.request_type == RequestType.STAGEIN:
            paths = __create_stagein_definitions(rws=rws,
                                                 sources=filtered_sources,
                                                 limit_dest_schemes=transfer_schemes,
                                                 operation_src='read',
                                                 operation_dest='write',
                                                 protocol_factory=protocol_factory)
        else:
            paths = __create_transfer_definitions(ctx,
                                                  rws=rws,
                                                  sources=filtered_sources,
                                                  multihop_rses=multihop_rses,
                                                  limit_dest_schemes=[],
                                                  operation_src='third_party_copy',
                                                  operation_dest='third_party_copy',
                                                  domain='wan',
                                                  protocol_factory=protocol_factory,
                                                  session=session)

        for source in filtered_sources:
            transfer_path = paths.get(source.rse.id)
            if transfer_path is None:
                logger(logging.WARNING, "%s: no path from %s to %s", rws.request_id, source.rse, rws.dest_rse)
                continue
            if not transfer_path:
                any_source_had_scheme_mismatch = True
                logger(logging.WARNING, "%s: no matching protocol between %s and %s", rws.request_id, source.rse, rws.dest_rse)
                continue

            if len(transfer_path) > 1:
                logger(logging.DEBUG, '%s: From %s to %s requires multihop: %s', rws.request_id, source.rse, rws.dest_rse, transfer_path_str(transfer_path))

            candidate_paths.append(transfer_path)

        if len(filtered_sources) != len(candidate_paths):
            logger(logging.DEBUG, '%s: Sources after path computation: %s', rws.request_id, [str(path[0].src.rse) for path in candidate_paths])

        candidate_paths = __filter_multihops_with_intermediate_tape(candidate_paths)
        candidate_paths = __compress_multihops(candidate_paths, rws.sources)
        candidate_paths = list(__sort_paths(candidate_paths))

        logger(logging.INFO, '%s: Ordered sources: %s%s',
               rws,
               ','.join(('multihop: ' if len(path) > 1 else '') + '{}:{}:{}'.format(path[0].src.rse, path[0].src.source_ranking, path[0].src.distance_ranking)
                        for path in candidate_paths[:num_sources_in_logs]),
               '... and %d others' % (len(candidate_paths) - num_sources_in_logs) if len(candidate_paths) > num_sources_in_logs else '')

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

    return candidate_paths_by_request_id, reqs_no_source, reqs_scheme_mismatch, reqs_only_tape_source


def __parse_request_transfertools(
        rws: "RequestWithSources",
        logger: "Callable" = logging.log,
):
    """
    Parse a set of desired transfertool names from the database field request.transfertool
    """
    request_transfertools = set()
    try:
        if rws.transfertool:
            request_transfertools = {tt.strip() for tt in rws.transfertool.split(',')}
    except Exception:
        logger(logging.WARN, "Unable to parse requested transfertools: {}".format(request_transfertools))
        request_transfertools = None
    return request_transfertools


def __assign_paths_to_transfertool_and_create_hops(
        candidate_paths_by_request_id: "Dict[str: List[DirectTransferDefinition]]",
        transfertools_by_name: "Optional[Dict[str, Type[Transfertool]]]" = None,
        logger: "Callable" = logging.log,
        session: "Optional[Session]" = None,
) -> "Tuple[Dict[TransferToolBuilder, List[DirectTransferDefinition]], Set[str], Set[str]]":
    """
    for each request, pick the first path which can be submitted by one of the transfertools.
    If the chosen path is multihop, create all missing intermediate requests and replicas.
    """
    reqs_no_host = set()
    reqs_unsupported_transfertool = set()
    paths_by_transfertool_builder = {}
    default_tombstone_delay = core_config_get('transfers', 'multihop_tombstone_delay', default=DEFAULT_MULTIHOP_TOMBSTONE_DELAY, expiration_time=600)
    for request_id, candidate_paths in candidate_paths_by_request_id.items():
        # Get the rws object from any candidate path. It is the same for all candidate paths. For multihop, the initial request is the last hop
        rws = candidate_paths[0][-1].rws

        request_transfertools = __parse_request_transfertools(rws, logger)
        if request_transfertools is None:
            # Parsing failed
            reqs_no_host.add(request_id)
            continue
        if request_transfertools and transfertools_by_name and not request_transfertools.intersection(transfertools_by_name):
            # The request explicitly asks for a transfertool which this submitter doesn't support
            reqs_unsupported_transfertool.add(request_id)
            continue

        # Selects the first path which can be submitted by a supported transfertool and for which the creation of
        # intermediate hops (if it is a multihop) work correctly
        best_path = None
        builder_to_use = None
        concurrent_submission_detected = False
        for transfer_path in candidate_paths:
            builder = None
            if transfertools_by_name:
                transfertools_to_try = set(transfertools_by_name)
                if request_transfertools:
                    transfertools_to_try = transfertools_to_try.intersection(request_transfertools)
                for transfertool in transfertools_to_try:
                    builder = transfertools_by_name[transfertool].submission_builder_for_path(transfer_path, logger=logger)
                    if builder:
                        break
            if builder or not transfertools_by_name:
                created, concurrent_submission_detected = create_missing_replicas_and_requests(
                    transfer_path, default_tombstone_delay, logger=logger, session=session
                )
                if created:
                    best_path = transfer_path
                    builder_to_use = builder
                if created or concurrent_submission_detected:
                    break

        if concurrent_submission_detected:
            logger(logging.INFO, '%s: Request is being handled by another submitter. Skipping for now.' % request_id)
            continue

        if not best_path:
            reqs_no_host.add(request_id)
            logger(logging.INFO, '%s: Cannot pick transfertool, or create intermediate requests' % request_id)
            continue

        if len(best_path) > 1:
            logger(logging.INFO, '%s: Best path is multihop: %s' % (rws.request_id, transfer_path_str(best_path)))
        elif best_path is not candidate_paths[0] or len(best_path[0].sources) > 1:
            # Only print singlehop if it brings additional information:
            # - either it's not the first candidate path
            # - or it's a multi-source
            # in other cases, it doesn't bring any additional information to what is known from previous logs
            logger(logging.INFO, '%s: Best path is direct: %s' % (rws.request_id, transfer_path_str(best_path)))

        paths_by_transfertool_builder.setdefault(builder_to_use, []).append(best_path)
    return paths_by_transfertool_builder, reqs_no_host, reqs_unsupported_transfertool


@transactional_session
def create_missing_replicas_and_requests(
        transfer_path: "List[DirectTransferDefinition]",
        default_tombstone_delay: int,
        logger: "Callable",
        session: "Optional[Session]" = None
) -> "Tuple[bool, bool]":
    """
    Create replicas and requests in the database for the intermediate hops
    """
    initial_request_id = transfer_path[-1].rws.request_id
    creation_successful = True
    concurrent_submission_detected = False
    created_requests = []
    # Iterate the path in reverse order. The last hop is the initial request, so
    # next_hop.rws.request_id will always be initialized when handling the current hop.
    for i in reversed(range(len(transfer_path))):
        hop = transfer_path[i]
        rws = hop.rws
        if rws.request_id:
            continue

        tombstone_delay = rws.dest_rse.attributes.get('multihop_tombstone_delay', default_tombstone_delay)
        try:
            tombstone = tombstone_from_delay(tombstone_delay)
        except ValueError:
            logger(logging.ERROR, "%s: Cannot parse multihop tombstone delay %s", initial_request_id, tombstone_delay)
            creation_successful = False
            break

        files = [{'scope': rws.scope,
                  'name': rws.name,
                  'bytes': rws.byte_count,
                  'adler32': rws.adler32,
                  'md5': rws.md5,
                  'tombstone': tombstone,
                  'state': 'C'}]
        try:
            add_replicas(rse_id=rws.dest_rse.id,
                         files=files,
                         account=rws.account,
                         ignore_availability=False,
                         dataset_meta=None,
                         session=session)
            # Set replica state to Copying in case replica already existed in another state.
            # Can happen when a multihop transfer failed previously, and we are re-scheduling it now.
            update_replica_state(rse_id=rws.dest_rse.id, scope=rws.scope, name=rws.name, state=ReplicaState.COPYING, session=session)
        except Exception as error:
            logger(logging.ERROR, '%s: Problem adding replicas on %s : %s', initial_request_id, rws.dest_rse, str(error))

        rws.attributes['next_hop_request_id'] = transfer_path[i + 1].rws.request_id
        rws.attributes['initial_request_id'] = initial_request_id
        rws.attributes['source_replica_expression'] = hop.src.rse.name
        new_req = queue_requests(requests=[{'dest_rse_id': rws.dest_rse.id,
                                            'scope': rws.scope,
                                            'name': rws.name,
                                            'rule_id': '00000000000000000000000000000000',  # Dummy Rule ID used for multihop. TODO: Replace with actual rule_id once we can flag intermediate requests
                                            'attributes': rws.attributes,
                                            'request_type': rws.request_type,
                                            'retry_count': rws.retry_count,
                                            'account': rws.account,
                                            'requested_at': datetime.datetime.now()}], session=session)
        # If a request already exists, new_req will be an empty list.
        if not new_req:
            creation_successful = False

            existing_request = get_request_by_did(rws.scope, rws.name, rws.dest_rse.id, session=session)
            if existing_request['requested_at'] and \
                    datetime.datetime.utcnow() - CONCURRENT_SUBMISSION_TOLERATION_DELAY < existing_request['requested_at']:
                concurrent_submission_detected = True

            break
        rws.request_id = new_req[0]['id']
        logger(logging.DEBUG, '%s: New request created for the transfer between %s and %s : %s', initial_request_id, transfer_path[0].src, transfer_path[-1].dst, rws.request_id)
        set_request_state(rws.request_id, RequestState.QUEUED, session=session, logger=logger)
        created_requests.append(rws.request_id)

    if not concurrent_submission_detected and not creation_successful:
        # Need to fail all the intermediate requests
        logger(logging.WARNING, '%s: Multihop : A request already exists for the transfer between %s and %s. Will cancel all the parent requests',
               initial_request_id, transfer_path[0].src, transfer_path[-1].dst)
        try:
            for request_id in created_requests:
                set_request_state(request_id=request_id, new_state=RequestState.FAILED,
                                  err_msg="Cancelled hop in multi-hop", session=session)
        except UnsupportedOperation:
            logger(logging.ERROR, '%s: Multihop : Cannot cancel all the parent requests : %s', initial_request_id, str(created_requests))

    return creation_successful, concurrent_submission_detected


@read_session
def __list_transfer_requests_and_source_replicas(
    total_workers=0,
    worker_number=0,
    partition_hash_var=None,
    limit=None,
    activity=None,
    older_than=None,
    rses=None,
    request_type=RequestType.TRANSFER,
    request_state=None,
    ignore_availability=False,
    transfertool=None,
    session=None,
) -> "List[RequestWithSources]":
    """
    List requests with source replicas
    :param total_workers:      Number of total workers.
    :param worker_number:      Id of the executing worker.
    :param partition_hash_var  The hash variable used for partitioning thread work
    :param limit:              Integer of requests to retrieve.
    :param activity:           Activity to be selected.
    :param older_than:         Only select requests older than this DateTime.
    :param rses:               List of rse_id to select requests.
    :param request_type:       Filter on the given request type.
    :param request_state:      Filter on the given request state
    :param transfertool:       The transfer tool as specified in rucio.cfg.
    :param ignore_availability Ignore blocklisted RSEs
    :param session:            Database session to use.
    :returns:                  List of RequestWithSources objects.
    """

    if partition_hash_var is None:
        partition_hash_var = 'requests.id'

    if request_state is None:
        request_state = RequestState.QUEUED

    sub_requests = session.query(models.Request.id,
                                 models.Request.rule_id,
                                 models.Request.scope,
                                 models.Request.name,
                                 models.Request.md5,
                                 models.Request.adler32,
                                 models.Request.bytes,
                                 models.Request.activity,
                                 models.Request.attributes,
                                 models.Request.previous_attempt_id,
                                 models.Request.dest_rse_id,
                                 models.Request.retry_count,
                                 models.Request.account,
                                 models.Request.created_at,
                                 models.Request.requested_at,
                                 models.Request.priority,
                                 models.Request.transfertool) \
        .with_hint(models.Request, "INDEX(REQUESTS REQUESTS_TYP_STA_UPD_IDX)", 'oracle') \
        .filter(models.Request.state == request_state) \
        .filter(models.Request.request_type == request_type) \
        .join(models.RSE, models.RSE.id == models.Request.dest_rse_id) \
        .filter(models.RSE.deleted == false()) \
        .order_by(models.Request.created_at)

    if not ignore_availability:
        sub_requests = sub_requests.filter(models.RSE.availability.in_((2, 3, 6, 7)))

    if isinstance(older_than, datetime.datetime):
        sub_requests = sub_requests.filter(models.Request.requested_at < older_than)

    if activity:
        sub_requests = sub_requests.filter(models.Request.activity == activity)

    # if a transfertool is specified make sure to filter for those requests and apply related index
    if transfertool:
        sub_requests = sub_requests.filter(models.Request.transfertool == transfertool)
        sub_requests = sub_requests.with_hint(models.Request, "INDEX(REQUESTS REQUESTS_TYP_STA_TRA_ACT_IDX)", 'oracle')
    else:
        sub_requests = sub_requests.with_hint(models.Request, "INDEX(REQUESTS REQUESTS_TYP_STA_UPD_IDX)", 'oracle')

    use_temp_tables = config_get_bool('core', 'use_temp_tables', default=False)
    if rses and use_temp_tables:
        temp_table_cls = create_temp_table(
            "list_transfer_requests_and_source_replicas",
            models.Column("rse_id", models.GUID()),
            session=session,
        )

        session.bulk_insert_mappings(temp_table_cls, [{'rse_id': rse_id} for rse_id in rses])

        sub_requests = sub_requests.join(temp_table_cls, temp_table_cls.rse_id == models.RSE.id)

    sub_requests = filter_thread_work(session=session, query=sub_requests, total_threads=total_workers, thread_id=worker_number, hash_variable=partition_hash_var)

    if limit:
        sub_requests = sub_requests.limit(limit)

    sub_requests = sub_requests.subquery()

    query = session.query(sub_requests.c.id,
                          sub_requests.c.rule_id,
                          sub_requests.c.scope,
                          sub_requests.c.name,
                          sub_requests.c.md5,
                          sub_requests.c.adler32,
                          sub_requests.c.bytes,
                          sub_requests.c.activity,
                          sub_requests.c.attributes,
                          sub_requests.c.previous_attempt_id,
                          sub_requests.c.dest_rse_id,
                          sub_requests.c.account,
                          sub_requests.c.retry_count,
                          sub_requests.c.priority,
                          sub_requests.c.transfertool,
                          sub_requests.c.requested_at,
                          models.RSE.id.label("source_rse_id"),
                          models.RSE.rse,
                          models.RSEFileAssociation.path,
                          models.Source.ranking.label("source_ranking"),
                          models.Source.url.label("source_url"),
                          models.Distance.ranking.label("distance_ranking")) \
        .order_by(sub_requests.c.created_at) \
        .outerjoin(models.RSEFileAssociation, and_(sub_requests.c.scope == models.RSEFileAssociation.scope,
                                                   sub_requests.c.name == models.RSEFileAssociation.name,
                                                   models.RSEFileAssociation.state == ReplicaState.AVAILABLE,
                                                   sub_requests.c.dest_rse_id != models.RSEFileAssociation.rse_id)) \
        .with_hint(models.RSEFileAssociation, "+ index(replicas REPLICAS_PK)", 'oracle') \
        .outerjoin(models.RSE, and_(models.RSE.id == models.RSEFileAssociation.rse_id,
                                    models.RSE.deleted == false())) \
        .outerjoin(models.Source, and_(sub_requests.c.id == models.Source.request_id,
                                       models.RSE.id == models.Source.rse_id)) \
        .with_hint(models.Source, "+ index(sources SOURCES_PK)", 'oracle') \
        .outerjoin(models.Distance, and_(sub_requests.c.dest_rse_id == models.Distance.dest_rse_id,
                                         models.RSEFileAssociation.rse_id == models.Distance.src_rse_id)) \
        .with_hint(models.Distance, "+ index(distances DISTANCES_PK)", 'oracle')

    # if transfertool specified, select only the requests where the source rses are set up for the transfer tool
    if transfertool:
        query = query.subquery()
        query = session.query(query) \
            .join(models.RSEAttrAssociation, models.RSEAttrAssociation.rse_id == query.c.source_rse_id) \
            .filter(models.RSEAttrAssociation.key == 'transfertool',
                    models.RSEAttrAssociation.value.like('%' + transfertool + '%'))

    requests_by_id = {}
    for (request_id, rule_id, scope, name, md5, adler32, byte_count, activity, attributes, previous_attempt_id, dest_rse_id, account, retry_count,
         priority, transfertool, requested_at, source_rse_id, source_rse_name, file_path, source_ranking, source_url, distance_ranking) in query:

        # If we didn't pre-filter using temporary tables on database side, perform the filtering here
        if not use_temp_tables and rses and dest_rse_id not in rses:
            continue

        request = requests_by_id.get(request_id)
        if not request:
            request = RequestWithSources(id_=request_id, request_type=request_type, rule_id=rule_id, scope=scope, name=name,
                                         md5=md5, adler32=adler32, byte_count=byte_count, activity=activity, attributes=attributes,
                                         previous_attempt_id=previous_attempt_id, dest_rse_data=RseData(id_=dest_rse_id),
                                         account=account, retry_count=retry_count, priority=priority, transfertool=transfertool,
                                         requested_at=requested_at)
            requests_by_id[request_id] = request

        if source_rse_id is not None:
            request.sources.append(TransferSource(rse_data=RseData(id_=source_rse_id, name=source_rse_name), file_path=file_path,
                                                  source_ranking=source_ranking, distance_ranking=distance_ranking, url=source_url))
    return list(requests_by_id.values())


@read_session
def __get_unavailable_rse_ids(operation, session=None, logger=logging.log):
    """
    :param logger:   Optional decorated logger that can be passed from the calling daemons or servers.
    Get unavailable rse ids for a given operation : read, write, delete
    """

    if operation not in ['read', 'write', 'delete']:
        logger(logging.ERROR, "Wrong operation specified : %s" % operation)
        return []
    key = 'unavailable_%s_rse_ids' % operation
    result = REGION_SHORT.get(key)
    if isinstance(result, NoValue):
        try:
            logger(logging.DEBUG, "Refresh unavailable %s rses" % operation)
            availability_key = 'availability_%s' % operation
            unavailable_rses = list_rses(filters={availability_key: False}, session=session)
            unavailable_rse_ids = [rse['id'] for rse in unavailable_rses]
            REGION_SHORT.set(key, unavailable_rse_ids)
            return unavailable_rse_ids
        except Exception:
            logger(logging.ERROR, "Failed to refresh unavailable %s rses, error" % operation, exc_info=True)
            return []
    return result


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


@transactional_session
def __load_inbound_distances_node(rse_id, session=None):
    """
    Loads the inbound edges of the distance graph for one node.
    :param rse_id:    RSE id to load the edges for.
    :param session:   The DB Session to use.
    :returns:         Dictionary based graph object.
    """

    result = REGION_SHORT.get('inbound_edges_%s' % str(rse_id))
    if isinstance(result, NoValue):
        inbound_edges = {}
        for distance in session.query(models.Distance).join(models.RSE, models.RSE.id == models.Distance.src_rse_id) \
                .filter(models.Distance.dest_rse_id == rse_id) \
                .filter(models.RSE.deleted == false()).all():
            if distance.ranking is None:
                continue
            ranking = distance.ranking if distance.ranking >= 0 else 0
            inbound_edges[distance.src_rse_id] = ranking
        REGION_SHORT.set('inbound_edges_%s' % str(rse_id), inbound_edges)
        result = inbound_edges
    return result


@transactional_session
def __load_outgoing_distances_node(rse_id, session=None):
    """
    Loads the outgoing edges of the distance graph for one node.
    :param rse_id:    RSE id to load the edges for.
    :param session:   The DB Session to use.
    :returns:         Dictionary based graph object.
    """

    result = REGION_SHORT.get('outgoing_edges_%s' % str(rse_id))
    if isinstance(result, NoValue):
        outgoing_edges = {}
        for distance in session.query(models.Distance).join(models.RSE, models.RSE.id == models.Distance.dest_rse_id)\
                               .filter(models.Distance.src_rse_id == rse_id)\
                               .filter(models.RSE.deleted == false()).all():
            if distance.ranking is None:
                continue
            ranking = distance.ranking if distance.ranking >= 0 else 0
            outgoing_edges[distance.dest_rse_id] = ranking
        REGION_SHORT.set('outgoing_edges_%s' % str(rse_id), outgoing_edges)
        result = outgoing_edges
    return result


@transactional_session
def __load_rse_settings(rse_id, session=None):
    """
    Loads the RSE settings from cache.
    :param rse_id:    RSE id to load the settings from.
    :param session:   The DB Session to use.
    :returns:         Dict of RSE Settings
    """

    result = REGION_SHORT.get('rse_settings_%s' % str(rse_id))
    if isinstance(result, NoValue):
        result = rsemgr.get_rse_info(rse=get_rse_name(rse_id=rse_id, session=session),
                                     vo=get_rse_vo(rse_id=rse_id, session=session),
                                     session=session)
        REGION_SHORT.set('rse_settings_%s' % str(rse_id), result)
    return result
