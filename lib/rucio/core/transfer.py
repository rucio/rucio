# -*- coding: utf-8 -*-
# Copyright 2013-2021 CERN
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
# - Martin Barisits <martin.barisits@cern.ch>, 2017-2021
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
# - Radu Carpa <radu.carpa@cern.ch>, 2021
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
from heapq import heappop, heappush
from typing import TYPE_CHECKING

from dogpile.cache import make_region
from dogpile.cache.api import NoValue
from sqlalchemy import and_, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql.expression import false

from rucio.common import constants
from rucio.common.config import config_get
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
from rucio.core.oidc import get_token_for_account_operation
from rucio.core.replica import add_replicas, tombstone_from_delay
from rucio.core.request import queue_requests, set_requests_state
from rucio.core.rse import get_rse_name, get_rse_vo, list_rses, get_rse_supported_checksums_from_attributes
from rucio.core.rse_expression_parser import parse_expression
from rucio.db.sqla import models, filter_thread_work
from rucio.db.sqla.constants import DIDType, RequestState, RSEType, RequestType, ReplicaState
from rucio.db.sqla.session import read_session, transactional_session
from rucio.rse import rsemanager as rsemgr
from rucio.transfertool.fts3 import FTS3Transfertool
from rucio.transfertool.mock import MockTransfertool

if TYPE_CHECKING:
    from typing import List

EXTRA_MODULES = import_extras(['globus_sdk'])

if EXTRA_MODULES['globus_sdk']:
    from rucio.transfertool.globus import GlobusTransferTool  # pylint: disable=import-error


"""
The core transfer.py is specifically for handling transfer-requests, thus requests
where the external_id is already known.
Requests accessed by request_id  are covered in the core request.py
"""

REGION_SHORT = make_region().configure('dogpile.cache.memcached',
                                       expiration_time=600,
                                       arguments={'url': config_get('cache', 'url', False, '127.0.0.1:11211'), 'distributed_lock': True})
ALLOW_USER_OIDC_TOKENS = config_get('conveyor', 'allow_user_oidc_tokens', False, False)
REQUEST_OIDC_SCOPE = config_get('conveyor', 'request_oidc_scope', False, 'fts:submit-transfer')
REQUEST_OIDC_AUDIENCE = config_get('conveyor', 'request_oidc_audience', False, 'fts:example')

WEBDAV_TRANSFER_MODE = config_get('conveyor', 'webdav_transfer_mode', False, None)

DEFAULT_MULTIHOP_TOMBSTONE_DELAY = datetime.timedelta(hours=2)


class RseData:
    """
    Helper data class storing rse data grouped in one place.
    """
    def __init__(self, id, name=None, attributes=None, info=None):
        self.id = id
        self.name = name
        self.attributes = attributes
        self.info = info

    def __str__(self):
        if self.name is not None:
            return "{}({})".format(self.name, self.id)
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
        return "source rse={}".format(self.rse)


class TransferDestination:
    def __init__(self, rse_data, scheme):
        self.rse = rse_data
        self.scheme = scheme

    def __str__(self):
        return "destination rse={}".format(self.rse)


class RequestWithSources:
    def __init__(self, id, request_type, rule_id, scope, name, md5, adler32, byte_count, activity, attributes,
                 previous_attempt_id, dest_rse_data, account, retry_count):

        self.request_id = id
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

        self.sources = []

    def __str__(self):
        return "request {}:{}({})".format(self.scope, self.name, self.request_id)

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
    def __init__(self, source, destination, rws, protocol_factory, operation_src, operation_dest):
        self.sources = [source]
        self.destination = destination

        self.rws = rws
        self.protocol_factory = protocol_factory
        self.operation_src = operation_src
        self.operation_dest = operation_dest

        self.legacy_def = {}

    def __str__(self):
        return 'transfer {} from {} to {}'.format(self.rws, ' and '.join([str(s) for s in self.sources]), self.dst.rse)

    @property
    def src(self):
        return self.sources[0]

    @property
    def dst(self):
        return self.destination

    def __setitem__(self, key, value):
        self.legacy_def[key] = value

    def __getitem__(self, key):
        if key == 'dest_urls':
            return [self.dest_url]
        if key == 'sources':
            return self.legacy_sources
        if key == 'use_ipv4':
            return self.use_ipv4
        return self.legacy_def[key]

    def get(self, key, default=None):
        if key == 'dest_urls':
            return [self.dest_url]
        if key == 'sources':
            return self.legacy_sources
        if key == 'use_ipv4':
            return self.use_ipv4
        return self.legacy_def.get(key, default)

    @property
    def dest_url(self):
        return self._dest_url(self.dst, self.rws, self.protocol_factory, self.operation_dest)

    @property
    def legacy_sources(self):
        return [
            (src.rse.name,
             self._source_url(src,
                              self.dst,
                              rws=self.rws,
                              protocol_factory=self.protocol_factory,
                              operation=self.operation_src),
             src.rse.id,
             src.source_ranking)
            for src in self.sources
        ]

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
    def _source_url(cls, src, dst, rws, protocol_factory, operation):
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
    def _dest_url(cls, dst, rws, protocol_factory, operation):
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

    def init_legacy_transfer_definition(self, bring_online, default_lifetime, logger):
        """
        initialize the legacy transfer definition:
        a dictionary with transfer parameters which were not yet migrated to the new, class-based, model
        """

        if self.legacy_def:
            return

        src = self.src
        dst = self.dst
        rws = self.rws

        # Extend the metadata dictionary with request attributes
        transfer_src_type = "DISK"
        transfer_dst_type = "DISK"
        overwrite, bring_online_local = True, None
        if src.rse.is_tape_or_staging_required():
            bring_online_local = bring_online
            transfer_src_type = "TAPE"
        if dst.rse.is_tape():
            overwrite = False
            transfer_dst_type = "TAPE"

        # Get dest space token
        dest_protocol = self.protocol_factory.protocol(dst.rse, dst.scheme, self.operation_dest)
        dest_spacetoken = None
        if dest_protocol.attributes and 'extended_attributes' in dest_protocol.attributes and \
                dest_protocol.attributes['extended_attributes'] and 'space_token' in dest_protocol.attributes['extended_attributes']:
            dest_spacetoken = dest_protocol.attributes['extended_attributes']['space_token']

        # get external_host + strict_copy + archive timeout
        strict_copy = dst.rse.attributes.get('strict_copy', False)
        archive_timeout = dst.rse.attributes.get('archive_timeout', None)

        # Fill the transfer dictionary including file_metadata
        file_metadata = {'request_id': rws.request_id,
                         'scope': rws.scope,
                         'name': rws.name,
                         'activity': rws.activity,
                         'request_type': self.rws.request_type,
                         'src_type': transfer_src_type,
                         'dst_type': transfer_dst_type,
                         'src_rse': src.rse.name,
                         'dst_rse': dst.rse.name,
                         'src_rse_id': src.rse.id,
                         'dest_rse_id': dst.rse.id,
                         'filesize': rws.byte_count,
                         'md5': rws.md5,
                         'adler32': rws.adler32,
                         'source_globus_endpoint_id': src.rse.attributes.get('globus_endpoint_id', None),
                         'dest_globus_endpoint_id': dst.rse.attributes.get('globus_endpoint_id', None)}
        transfer = {'request_id': rws.request_id,
                    'account': rws.account,
                    'src_spacetoken': None,
                    'dest_spacetoken': dest_spacetoken,
                    'overwrite': overwrite,
                    'bring_online': bring_online_local,
                    'copy_pin_lifetime': rws.attributes.get('lifetime', default_lifetime),
                    'selection_strategy': 'auto',
                    'rule_id': rws.rule_id,
                    'file_metadata': file_metadata}
        if strict_copy:
            transfer['strict_copy'] = strict_copy
        if archive_timeout and dst.rse.is_tape():
            try:
                transfer['archive_timeout'] = int(archive_timeout)
                logger(logging.DEBUG, 'Added archive timeout to transfer.')
            except ValueError:
                logger(logging.WARNING, 'Could not set archive_timeout for %s. Must be integer.', self)
                pass

        self.legacy_def = transfer


class StageinTransferDefinition(DirectTransferDefinition):
    """
    A definition of a transfer which triggers a stagein operation.
        - The source and destination url are identical
        - must be from TAPE to non-TAPE RSE
        - can only have one source
        - bring_online must be set
    """
    def __init__(self, source, destination, rws, protocol_factory, operation_src, operation_dest):
        if not source.rse.is_tape() or destination.rse.is_tape():
            raise RucioException("Stageing request {} must be from TAPE to DISK rse. Got {} and {}.".format(rws, source, destination))
        super().__init__(source, destination, rws, protocol_factory, operation_src, operation_dest)

    @property
    def dest_url(self):
        return self.src.url if self.src.url else self._source_url(self.src,
                                                                  self.dst,
                                                                  rws=self.rws,
                                                                  protocol_factory=self.protocol_factory,
                                                                  operation=self.operation_dest)

    @property
    def legacy_sources(self):
        return [(
            self.src.rse.name,
            self.dest_url,  # Source and dest url is the same for stagein requests
            self.src.rse.id,
            self.src.source_ranking
        )]

    def init_legacy_transfer_definition(self, bring_online, default_lifetime, logger):
        if not bring_online:
            raise RucioException("Stageing request {} requires bring_online to be set. Got {}".format(self.rws, bring_online))

        return super().init_legacy_transfer_definition(bring_online, default_lifetime, logger)


def oidc_supported(transfer_hop):
    """
    checking OIDC AuthN/Z support per destination and source RSEs;

    for oidc_support to be activated, all sources and the destination must explicitly support it
    """
    # assumes use of boolean 'oidc_support' RSE attribute
    if not transfer_hop.dst.rse.attributes.get('oidc_support', False):
        return False

    for source in transfer_hop.sources:
        if not source.rse.attributes.get('oidc_support', False):
            return False
    return True


def checksum_validation_strategy(src_attributes, dst_attributes, logger):
    """
    Compute the checksum validation strategy (none, source, destination or both) and the
    supported checksums from the attributes of the source and destination RSE.
    """
    source_supported_checksums = get_rse_supported_checksums_from_attributes(src_attributes)
    dest_supported_checksums = get_rse_supported_checksums_from_attributes(dst_attributes)
    common_checksum_names = set(source_supported_checksums).intersection(dest_supported_checksums)

    verify_checksum = 'both'
    if not dst_attributes.get('verify_checksum', True):
        if not src_attributes.get('verify_checksum', True):
            verify_checksum = 'none'
        else:
            verify_checksum = 'source'
    else:
        if not src_attributes.get('verify_checksum', True):
            verify_checksum = 'destination'
        else:
            verify_checksum = 'both'

    if len(common_checksum_names) == 0:
        logger(logging.INFO, 'No common checksum method. Verifying destination only.')
        verify_checksum = 'destination'

    if source_supported_checksums == ['none']:
        if dest_supported_checksums == ['none']:
            # both endpoints support none
            verify_checksum = 'none'
        else:
            # src supports none but dst does
            verify_checksum = 'destination'
    else:
        if dest_supported_checksums == ['none']:
            # source supports some but destination does not
            verify_checksum = 'source'
        else:
            if len(common_checksum_names) == 0:
                # source and dst support some bot none in common (dst priority)
                verify_checksum = 'destination'
            else:
                # Don't override the value in the file_metadata
                pass

    checksums_to_use = ['none']
    if verify_checksum == 'both':
        checksums_to_use = common_checksum_names
    elif verify_checksum == 'source':
        checksums_to_use = source_supported_checksums
    elif verify_checksum == 'destination':
        checksums_to_use = dest_supported_checksums

    return verify_checksum, checksums_to_use


def submit_bulk_transfers(external_host, files, transfertool='fts3', job_params={}, timeout=None, logger=logging.log):
    """
    Submit transfer request to a transfertool.
    :param external_host:  External host name as string
    :param files:          List of Dictionary containing request file.
    :param transfertool:   Transfertool as a string.
    :param job_params:     Metadata key/value pairs for all files as a dictionary.
    :param logger:         Optional decorated logger that can be passed from the calling daemons or servers.
    :returns:              Transfertool external ID.
    """

    record_counter('core.request.submit_transfer')

    transfer_id = None

    if transfertool == 'fts3':
        start_time = time.time()
        job_files = []
        for file in files:
            job_file = {}
            for key in file:
                if key == 'sources':
                    # convert sources from (src_rse, url, src_rse_id, rank) to url
                    job_file[key] = []
                    for source in file[key]:
                        job_file[key].append(source[1])
                else:
                    job_file[key] = file[key]
            job_files.append(job_file)

        # getting info about account and OIDC support of the RSEs
        use_oidc = job_params.get('use_oidc', False)
        transfer_token = None
        if use_oidc:
            logger(logging.DEBUG, 'OAuth2/OIDC available at RSEs')
            account = job_params.get('account', None)
            getadmintoken = False
            if ALLOW_USER_OIDC_TOKENS is False:
                getadmintoken = True
            logger(logging.DEBUG, 'Attempting to get a token for account %s. Admin token option set to %s' % (account, getadmintoken))
            # find the appropriate OIDC token and exchange it (for user accounts) if necessary
            token_dict = get_token_for_account_operation(account, req_audience=REQUEST_OIDC_AUDIENCE, req_scope=REQUEST_OIDC_SCOPE, admin=getadmintoken)
            if token_dict is not None:
                logger(logging.DEBUG, 'Access token has been granted.')
                if 'token' in token_dict:
                    logger(logging.DEBUG, 'Access token used as transfer token.')
                    transfer_token = token_dict['token']
        transfer_id = FTS3Transfertool(external_host=external_host, token=transfer_token).submit(files=job_files, job_params=job_params, timeout=timeout)
        record_timer('core.request.submit_transfers_fts3', (time.time() - start_time) * 1000 / len(files))
    elif transfertool == 'globus':
        logger(logging.DEBUG, '... Starting globus xfer ...')
        job_files = []
        for file in files:
            job_file = {}
            for key in file:
                if key == 'sources':
                    # convert sources from (src_rse, url, src_rse_id, rank) to url
                    job_file[key] = []
                    for source in file[key]:
                        job_file[key].append(source[1])
                else:
                    job_file[key] = file[key]
            job_files.append(job_file)
        logger(logging.DEBUG, 'job_files: %s' % job_files)
        transfer_id = GlobusTransferTool(external_host=None).bulk_submit(submitjob=job_files, timeout=timeout)
    elif transfertool == 'mock':
        transfer_id = MockTransfertool(external_host=None).submit(files, None)
    return transfer_id


@transactional_session
def prepare_sources_for_transfers(transfers, session=None):
    """
    Prepare the sources for transfers.
    :param transfers:  Dictionary containing request transfer info.
    :param session:    Database session to use.
    """

    try:
        for request_id in transfers:
            rowcount = session.query(models.Request)\
                              .filter_by(id=request_id)\
                              .filter(models.Request.state == RequestState.QUEUED)\
                              .update({'state': transfers[request_id]['state'],
                                       'external_id': transfers[request_id]['external_id'],
                                       'external_host': transfers[request_id]['external_host'],
                                       'dest_url': transfers[request_id]['dest_url'],
                                       'submitted_at': datetime.datetime.utcnow()},
                                      synchronize_session=False)
            if rowcount == 0:
                raise RequestNotFound("Failed to prepare transfer: request %s does not exist or is not in queued state" % request_id)

            if 'file' in transfers[request_id]:
                file = transfers[request_id]['file']
                for src_rse, src_url, src_rse_id, rank in file['sources']:
                    src_rowcount = session.query(models.Source)\
                                          .filter_by(request_id=request_id)\
                                          .filter(models.Source.rse_id == src_rse_id)\
                                          .update({'is_using': True}, synchronize_session=False)
                    if src_rowcount == 0:
                        models.Source(request_id=file['metadata']['request_id'],
                                      scope=file['metadata']['scope'],
                                      name=file['metadata']['name'],
                                      rse_id=src_rse_id,
                                      dest_rse_id=file['metadata']['dest_rse_id'],
                                      ranking=rank if rank else 0,
                                      bytes=file['metadata']['filesize'],
                                      url=src_url,
                                      is_using=True).\
                            save(session=session, flush=False)

    except IntegrityError as error:
        raise RucioException(error.args)


@transactional_session
def set_transfers_state(transfers, submitted_at, session=None):
    """
    Update the transfer info of a request.
    :param transfers:  Dictionary containing request transfer info.
    :param session:    Database session to use.
    """

    try:
        for request_id in transfers:
            rowcount = session.query(models.Request)\
                              .filter_by(id=request_id)\
                              .filter(models.Request.state == RequestState.SUBMITTING)\
                              .update({'state': transfers[request_id]['state'],
                                       'external_id': transfers[request_id]['external_id'],
                                       'external_host': transfers[request_id]['external_host'],
                                       'source_rse_id': transfers[request_id]['src_rse_id'],
                                       'submitted_at': submitted_at},
                                      synchronize_session=False)
            if rowcount == 0:
                raise RucioException("Failed to set requests %s tansfer %s: request doesn't exist or is not in SUBMITTING state" % (request_id, transfers[request_id]))

            request_type = transfers[request_id].get('request_type', None)

            msg = {'request-id': request_id,
                   'request-type': request_type,
                   'scope': transfers[request_id]['scope'].external,
                   'name': transfers[request_id]['name'],
                   'src-rse-id': transfers[request_id]['metadata'].get('src_rse_id', None),
                   'src-rse': transfers[request_id]['metadata'].get('src_rse', None),
                   'dst-rse-id': transfers[request_id]['metadata'].get('dst_rse_id', None),
                   'dst-rse': transfers[request_id]['metadata'].get('dst_rse', None),
                   'state': transfers[request_id]['state'],
                   'activity': transfers[request_id]['metadata'].get('activity', None),
                   'file-size': transfers[request_id]['metadata'].get('filesize', None),
                   'bytes': transfers[request_id]['metadata'].get('filesize', None),
                   'checksum-md5': transfers[request_id]['metadata'].get('md5', None),
                   'checksum-adler': transfers[request_id]['metadata'].get('adler32', None),
                   'external-id': transfers[request_id]['external_id'],
                   'external-host': transfers[request_id]['external_host'],
                   'queued_at': str(submitted_at)}
            if transfers[request_id]['scope'].vo != 'def':
                msg['vo'] = transfers[request_id]['scope'].vo

            if msg['request-type']:
                transfer_status = '%s-%s' % (msg['request-type'].name, msg['state'].name)
            else:
                transfer_status = 'transfer-%s' % msg['state']
            transfer_status = transfer_status.lower()

            message_core.add_message(transfer_status, msg, session=session)

    except IntegrityError as error:
        raise RucioException(error.args)


def bulk_query_transfers(request_host, transfer_ids, transfertool='fts3', timeout=None, logger=logging.log):
    """
    Query the status of a transfer.
    :param request_host:  Name of the external host.
    :param transfer_ids:  List of (External-ID as a 32 character hex string)
    :param transfertool:  Transfertool name as a string.
    :param logger:        Optional decorated logger that can be passed from the calling daemons or servers.
    :returns:             Request status information as a dictionary.
    """

    record_counter('core.request.bulk_query_transfers')

    if transfertool == 'fts3':
        try:
            start_time = time.time()
            fts_resps = FTS3Transfertool(external_host=request_host).bulk_query(transfer_ids=transfer_ids, timeout=timeout)
            record_timer('core.request.bulk_query_transfers', (time.time() - start_time) * 1000 / len(transfer_ids))
        except Exception:
            raise

        for transfer_id in transfer_ids:
            if transfer_id not in fts_resps:
                fts_resps[transfer_id] = Exception("Transfer id %s is not returned" % transfer_id)
            if fts_resps[transfer_id] and not isinstance(fts_resps[transfer_id], Exception):
                for request_id in fts_resps[transfer_id]:
                    status_dict = fts_resps[transfer_id][request_id]
                    job_state = status_dict['job_state']
                    file_state = status_dict['file_state']
                    if job_state in (FTS_STATE.FAILED, FTS_STATE.CANCELED):
                        status_dict['new_state'] = RequestState.FAILED
                    elif job_state == FTS_STATE.FINISHED:
                        status_dict['new_state'] = RequestState.DONE
                    elif job_state == FTS_STATE.FINISHEDDIRTY:
                        # Job partially completed. Verify the state of the file in the job
                        if file_state in (FTS_STATE.FAILED, FTS_STATE.CANCELED):
                            status_dict['new_state'] = RequestState.FAILED
                        elif file_state == FTS_STATE.FINISHED:
                            status_dict['new_state'] = RequestState.DONE
        return fts_resps
    elif transfertool == 'globus':
        try:
            start_time = time.time()
            logger(logging.DEBUG, 'transfer_ids: %s' % transfer_ids)
            responses = GlobusTransferTool(external_host=None).bulk_query(transfer_ids=transfer_ids, timeout=timeout)
            record_timer('core.request.bulk_query_transfers', (time.time() - start_time) * 1000 / len(transfer_ids))
        except Exception:
            raise

        for k, v in responses.items():
            if v == 'FAILED':
                responses[k] = RequestState.FAILED
            elif v == 'SUCCEEDED':
                responses[k] = RequestState.DONE
            else:
                responses[k] = RequestState.SUBMITTED
        return responses
    else:
        raise NotImplementedError

    return None


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


def query_latest(external_host, state, last_nhours=1, logger=logging.log):
    """
    Query the latest transfers in last n hours with state.
    :param external_host:  FTS host name as a string.
    :param state:          FTS job state as a string or a dictionary.
    :param last_nhours:    Latest n hours as an integer.
    :param logger:         Optional decorated logger that can be passed from the calling daemons or servers.
    :returns:              Requests status information as a dictionary.
    """

    record_counter('core.request.query_latest')

    start_time = time.time()
    resps = FTS3Transfertool(external_host=external_host).query_latest(state=state, last_nhours=last_nhours)
    record_timer('core.request.query_latest_fts3.%s.%s_hours' % (external_host, last_nhours), (time.time() - start_time) * 1000)

    if not resps:
        return

    ret_resps = []
    for resp in resps:
        if 'job_metadata' not in resp or resp['job_metadata'] is None or 'issuer' not in resp['job_metadata'] or resp['job_metadata']['issuer'] != 'rucio':
            continue

        if 'request_id' not in resp['job_metadata']:
            # submitted by new submitter
            try:
                logger(logging.DEBUG, "Transfer %s on %s is %s, decrease its updated_at." % (resp['job_id'], external_host, resp['job_state']))
                set_transfer_update_time(external_host, resp['job_id'], datetime.datetime.utcnow() - datetime.timedelta(hours=24))
            except Exception as error:
                logger(logging.DEBUG, "Exception happened when updating transfer updatetime: %s" % str(error).replace('\n', ''))

    return ret_resps


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
def update_transfer_state(external_host, transfer_id, state, session=None, logger=logging.log):
    """
    Used by poller to update the internal state of transfer,
    after the response by the external transfertool.
    :param request_host:          Name of the external host.
    :param transfer_id:           External transfer job id as a string.
    :param state:                 Request state as a string.
    :param session:               The database session to use.
    :param logger:                Optional decorated logger that can be passed from the calling daemons or servers.
    :returns commit_or_rollback:  Boolean.
    """

    try:
        if state == RequestState.LOST:
            reqs = request_core.get_requests_by_transfer(external_host, transfer_id, session=session)
            for req in reqs:
                logger(logging.INFO, 'REQUEST %s OF TRANSFER %s ON %s STATE %s' % (str(req['request_id']), external_host, transfer_id, str(state)))
                src_rse_id = req.get('source_rse_id', None)
                dst_rse_id = req.get('dest_rse_id', None)
                src_rse = None
                dst_rse = None
                if src_rse_id:
                    src_rse = get_rse_name(src_rse_id, session=session)
                if dst_rse_id:
                    dst_rse = get_rse_name(dst_rse_id, session=session)
                response = {'new_state': state,
                            'transfer_id': transfer_id,
                            'job_state': state,
                            'src_url': None,
                            'dst_url': req['dest_url'],
                            'duration': 0,
                            'reason': "The FTS job lost",
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
                            'external_host': external_host,
                            'job_m_replica': None,
                            'created_at': req.get('created_at', None),
                            'submitted_at': req.get('submitted_at', None),
                            'details': None,
                            'account': req.get('account', None)}

                err_msg = request_core.get_transfer_error(response['new_state'], response['reason'] if 'reason' in response else None)
                request_core.set_request_state(req['request_id'],
                                               response['new_state'],
                                               transfer_id=transfer_id,
                                               src_rse_id=src_rse_id,
                                               err_msg=err_msg,
                                               session=session)

                request_core.add_monitor_message(req, response, session=session)
        else:
            __set_transfer_state(external_host, transfer_id, state, session=session)
        return True
    except UnsupportedOperation as error:
        logger(logging.WARNING, "Transfer %s on %s doesn't exist - Error: %s" % (transfer_id, external_host, str(error).replace('\n', '')))
        return False


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


def __search_shortest_paths(source_rse_ids, dest_rse_id, operation_src, operation_dest, domain, multihop_rses,
                            limit_dest_schemes, inbound_links_by_node=None, session=None):
    """
    Find the shortest paths from multiple sources towards dest_rse_id.
    Does a Backwards Dijkstra's algorithm: start from destination and follow inbound links towards the sources.
    If multihop is disabled, stop after analysing direct connections to dest_rse. Otherwise, stops when all
    sources where found or the graph was traversed in integrality.

    The inbound links retrieved from the database can be accumulated into the inbound_links_by_node, passed
    from the calling context. To be able to reuse them.
    """
    if not limit_dest_schemes:
        limit_dest_schemes = []

    if multihop_rses is None:
        multihop_rses = []

    HOP_PENALTY = core_config_get('transfers', 'hop_penalty', default=10, session=session)  # Penalty to be applied to each further hop

    if multihop_rses:
        # Filter out island source RSEs
        sources_to_find = {rse_id for rse_id in source_rse_ids if __load_outgoing_distances_node(rse_id=rse_id, session=session)}
    else:
        sources_to_find = set(source_rse_ids)

    next_hop = {dest_rse_id: {'cumulated_distance': 0}}
    priority_q = []

    remaining_sources = copy.copy(sources_to_find)
    heappush(priority_q, (0, dest_rse_id))
    while priority_q:
        pq_distance, current_node = heappop(priority_q)

        current_distance = next_hop[current_node]['cumulated_distance']
        if pq_distance > current_distance:
            # Lazy deletion.
            # We don't update the priorities in the queue. The same element can be found multiple times,
            # with different priorities. Skip this element if it was already processed.
            continue

        if current_node in remaining_sources:
            remaining_sources.remove(current_node)
        if not remaining_sources:
            # We found the shortest paths to all desired sources
            break

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
                heappush(priority_q, (new_adjacent_distance, adjacent_node))
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
def __create_transfer_definitions(ctx, protocol_factory, rws, sources, multihop_rses, limit_dest_schemes,
                                  operation_src, operation_dest, domain, session=None):
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
                    id=None,
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


def __create_stagein_definitions(rws, sources, limit_dest_schemes, operation_src, operation_dest, protocol_factory):
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


def __filter_unwanted_paths(candidate_paths):

    # Discard multihop transfers which contain a tape source as an intermediate hop
    filtered_candidate_paths = []
    for path in candidate_paths:
        if any(transfer.src.rse.is_tape_or_staging_required() for transfer in path[1:]):
            continue
        filtered_candidate_paths.append(path)
    candidate_paths = filtered_candidate_paths

    # Discard multihop transfers which contain other candidate as part of itself For example:
    # if A->B->C and B->C are both candidates, discard A->B->C because it includes B->C. Doing B->C is enough.
    source_rses = {path[0].src.rse.id for path in candidate_paths}
    filtered_candidate_paths = []
    for path in candidate_paths:
        if any(hop.src.rse.id in source_rses for hop in path[1:]):
            continue
        filtered_candidate_paths.append(path)
    candidate_paths = filtered_candidate_paths

    yield from candidate_paths


def __sort_paths(candidate_paths):

    def __transfer_order_key(transfer_path):
        # higher source_ranking first,
        # on equal source_ranking, prefer DISK over TAPE
        # on equal type, prefer lower distance_ranking
        # on equal distance, prefer single hop
        return (
            - transfer_path[0].src.source_ranking,
            transfer_path[0].src.rse.is_tape_or_staging_required(),  # rely on the fact that False < True
            transfer_path[0].src.distance_ranking,
            len(transfer_path) > 1,  # rely on the fact that False < True
        )

    yield from sorted(candidate_paths, key=__transfer_order_key)


def __filter_for_transfertool(candidate_paths, transfertool, retry_other_fts, logger):
    """
    Filter out paths which cannot be handled by the given transfertool (missing globus enpoint ids; no common fts server attribute; etc)
    Generates tuples: (<the external host which can handle the transfer>, <the associated transfer path>)
    An empty string is a valid external host.
    """
    for transfer_path in candidate_paths:
        # The last hop is the initial transfer for multihops
        rws = transfer_path[-1].rws

        external_host = ''
        if transfertool == 'globus':
            all_rses_have_globus_id = True
            for hop in transfer_path:
                source_globus_endpoint_id = hop.src.rse.attributes.get('globus_endpoint_id', None)
                dest_globus_endpoint_id = hop.dst.rse.attributes.get('globus_endpoint_id', None)
                if not source_globus_endpoint_id or not dest_globus_endpoint_id:
                    all_rses_have_globus_id = False
                    break

            if not all_rses_have_globus_id:
                logger(logging.ERROR, 'Globus endpoint attribute not defined - for at least one transfer hops {} {}'.format(','.join(transfer_path), rws.request_id))
                continue
        else:
            common_fts_hosts = []
            for hop in transfer_path:
                fts_hosts = hop.dst.rse.attributes.get('fts', None)
                if hop.src.rse.attributes.get('sign_url', None) == 'gcs':
                    fts_hosts = hop.src.rse.attributes.get('fts', None)
                fts_hosts = fts_hosts.split(",") if fts_hosts else []

                common_fts_hosts = fts_hosts if not common_fts_hosts else list(set(common_fts_hosts).intersection(fts_hosts))
                if not common_fts_hosts:
                    break

            if common_fts_hosts:
                external_host = common_fts_hosts[0]
                if retry_other_fts:
                    external_host = common_fts_hosts[rws.retry_count % len(common_fts_hosts)]
            else:
                if transfertool == 'fts3':
                    logger(logging.ERROR, 'FTS attribute not defined - for at least one transfer hops {} {}'.format(','.join(transfer_path), rws.request_id))
                    continue
                else:
                    external_host = ''

        yield external_host, transfer_path


@transactional_session
def next_transfers_to_submit(total_workers=0, worker_number=0, limit=None, activity=None, older_than=None, rses=None, schemes=None,
                             retry_other_fts=False, failover_schemes=None, transfertool=None, request_type=RequestType.TRANSFER,
                             logger=logging.log, session=None):
    """
    Get next transfers to be submitted; grouped by the external host to which they will be submitted
    :param total_workers:         Number of total workers.
    :param worker_number:         Id of the executing worker.
    :param limit:                 Maximum number of requests to retrieve from database.
    :param activity:              Activity.
    :param older_than:            Get transfers older than.
    :param rses:                  Include RSES.
    :param schemes:               Include schemes.
    :param retry_other_fts:       Retry other fts servers.
    :param failover_schemes:      Failover schemes.
    :param transfertool:          The transfer tool as specified in rucio.cfg.
    :param request_type           The type of requests to retrieve (Transfer/Stagein)
    :param logger:                Optional decorated logger that can be passed from the calling daemons or servers.
    :param session:               The database session in use.
    :returns:                     Dict: {external_host: list of transfers (possibly multihop) to be submitted to this host}

    Workflow:
    """

    include_multihop = False
    if transfertool in ['fts3', None]:
        include_multihop = core_config_get('transfers', 'use_multihop', default=False, expiration_time=600, session=session)

    multihop_rses = []
    if include_multihop:
        try:
            multihop_rses = [rse['id'] for rse in parse_expression('available_for_multihop=true')]
        except InvalidRSEExpression:
            pass

    # retrieve (from the database) the transfer requests with their possible source replicas
    request_with_sources = __list_transfer_requests_and_source_replicas(
        total_workers=total_workers,
        worker_number=worker_number,
        limit=limit,
        activity=activity,
        older_than=older_than,
        rses=rses,
        request_type=request_type,
        request_state=RequestState.QUEUED,
        transfertool=transfertool,
        session=session,
    )

    # for each source, compute the (possibly multihop) path between it and the transfer destination
    candidate_paths, reqs_no_source, reqs_scheme_mismatch, reqs_only_tape_source = __build_transfer_paths(
        request_with_sources,
        multihop_rses=multihop_rses,
        schemes=schemes,
        failover_schemes=failover_schemes,
        logger=logger,
        session=session,
    )

    # pick the best path among the ones computed previously
    # if the chosen best path is a multihop, create intermediate replicas and the intermediate transfer requests
    paths_by_external_host, reqs_no_host = __pick_and_build_path_for_transfertool(
        candidate_paths,
        transfertool=transfertool,
        retry_other_fts=retry_other_fts,
        logger=logger
    )

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

    return paths_by_external_host


def __build_transfer_paths(requests_with_sources, multihop_rses=None, schemes=None, failover_schemes=None, logger=logging.log, session=None):
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

    candidate_paths_by_request_id, reqs_no_source, reqs_only_tape_source, reqs_scheme_mismatch = {}, set(), set(), set()
    for rws in requests_with_sources:

        ctx.ensure_fully_loaded(rws.dest_rse)
        for source in rws.sources:
            ctx.ensure_fully_loaded(source.rse)

        transfer_schemes = schemes
        if rws.previous_attempt_id and failover_schemes:
            transfer_schemes = failover_schemes

        logger(logging.DEBUG, 'Found following sources for %s: %s', rws, [str(src.rse) for src in rws.sources])
        # Assume request doesn't have any sources. Will be removed later if sources are found.
        reqs_no_source.add(rws.request_id)

        # Check if destination is blocked
        if rws.dest_rse.id in unavailable_write_rse_ids:
            logger(logging.WARNING, 'RSE %s is blocked for write. Will skip the submission of new jobs', rws.dest_rse)
            continue

        # parse source expression
        source_replica_expression = rws.attributes.get('source_replica_expression', None)
        allowed_source_rses = None
        if source_replica_expression:
            try:
                parsed_rses = parse_expression(source_replica_expression, session=session)
            except InvalidRSEExpression as error:
                logger(logging.ERROR, "Invalid RSE exception %s: %s", source_replica_expression, str(error))
                continue
            else:
                allowed_source_rses = [x['id'] for x in parsed_rses]

        filtered_sources = rws.sources
        # Only keep allowed sources
        if allowed_source_rses is not None:
            filtered_sources = filter(lambda s: s.rse.id in allowed_source_rses, filtered_sources)
        filtered_sources = filter(lambda s: s.rse.name is not None, filtered_sources)
        # Ignore blocklisted RSEs
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
            logger(logging.DEBUG, 'Sources after filtering for %s: %s', rws, [str(src.rse) for src in filtered_sources])
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
                                                  limit_dest_schemes=None,
                                                  operation_src='third_party_copy',
                                                  operation_dest='third_party_copy',
                                                  domain='wan',
                                                  protocol_factory=protocol_factory,
                                                  session=session)

        for source in filtered_sources:
            transfer_path = paths.get(source.rse.id)
            if transfer_path is None:
                logger(logging.WARNING, "Request %s: no path from %s to %s", rws.request_id, source.rse, rws.dest_rse)
                continue
            if not transfer_path:
                any_source_had_scheme_mismatch = True
                logger(logging.WARNING, "Request %s: no matching protocol between %s and %s", rws.request_id, source.rse, rws.dest_rse)
                continue

            if len(transfer_path) > 1:
                logger(logging.DEBUG, 'From %s to %s requires multihop: %s', source.rse, rws.dest_rse, [str(hop) for hop in transfer_path])

            candidate_paths.append(transfer_path)

        if len(filtered_sources) != len(candidate_paths):
            logger(logging.DEBUG, 'Sources after path computation for %s: %s', rws, [str(path[0].src.rse) for path in candidate_paths])

        candidate_paths = __filter_unwanted_paths(candidate_paths)
        candidate_paths = list(__sort_paths(candidate_paths))

        if not candidate_paths:
            # It can happen that some sources are skipped because they are TAPE, and others because
            # of scheme mismatch. However, we can only have one state in the database. I picked to
            # prioritize setting only_tape_source without any particular reason.
            if had_tape_sources and not filtered_sources:
                logger(logging.DEBUG, 'Only tape sources found for %s' % rws)
                reqs_only_tape_source.add(rws.request_id)
                reqs_no_source.remove(rws.request_id)
            elif any_source_had_scheme_mismatch:
                logger(logging.DEBUG, 'Scheme mismatch detected for %s' % rws)
                reqs_scheme_mismatch.add(rws.request_id)
                reqs_no_source.remove(rws.request_id)
            else:
                logger(logging.DEBUG, 'No candidate path found for %s' % rws)
            continue

        candidate_paths_by_request_id[rws.request_id] = candidate_paths
        reqs_no_source.remove(rws.request_id)

    return candidate_paths_by_request_id, reqs_no_source, reqs_scheme_mismatch, reqs_only_tape_source


def __pick_and_build_path_for_transfertool(candidate_paths_by_request_id, retry_other_fts=False, transfertool=None, logger=logging.log):
    """
    for each request, pick the first path which can be submitted to the transfertool given in parameter.
    If the chosen path is multihop, create all missing intermediate requests and replicas.
    """
    reqs_no_host = set()
    transfers_by_host = {}
    default_tombstone_delay = core_config_get('transfers', 'multihop_tombstone_delay', default=DEFAULT_MULTIHOP_TOMBSTONE_DELAY, expiration_time=600)
    for request_id, candidate_paths in candidate_paths_by_request_id.items():

        # Selects the first path which can be submitted by the given transfertool and for which the creation of
        # intermediate hops (if it is a multihop) work correctly
        best_path = None
        external_host = None
        for external_host, transfer_path in __filter_for_transfertool(candidate_paths, transfertool, retry_other_fts, logger):
            if create_missing_replicas_and_requests(transfer_path, default_tombstone_delay, logger=logger):
                best_path = transfer_path
                break

        if not best_path:
            reqs_no_host.add(request_id)
            logger(logging.DEBUG, 'Cannot assign transfer host, or create intermediate requests for %s' % request_id)
            continue

        # For multihop, the initial request is the last hop
        rws = best_path[-1].rws
        if len(best_path) > 1:
            logger(logging.DEBUG, 'Best path is multihop for %s: %s' % (rws, [str(hop) for hop in best_path]))
        else:
            logger(logging.DEBUG, 'Best path is direct for %s: %s' % (rws, best_path[0]))

        transfers_by_host.setdefault(external_host, []).append(best_path)
    return transfers_by_host, reqs_no_host


@transactional_session
def create_missing_replicas_and_requests(transfer_path, default_tombstone_delay, logger, session=None):
    # Create replicas and requests in the database for the intermediate hops
    creation_successful = True
    created_requests = []
    for hop in transfer_path:
        rws = hop.rws
        if rws.request_id:
            continue

        if 'multihop_tombstone_delay' in rws.dest_rse.attributes:
            tombstone = tombstone_from_delay(rws.dest_rse.attributes['multihop_tombstone_delay'])
        else:
            tombstone = tombstone_from_delay(default_tombstone_delay)
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
        except Exception as error:
            logger(logging.ERROR, 'Problem adding replicas %s:%s on %s : %s', rws.scope, rws.name, rws.dest_rse, str(error))

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
            break
        rws.request_id = new_req[0]['id']
        logger(logging.DEBUG, 'New request created for the transfer between %s and %s : %s', transfer_path[0].src, transfer_path[-1].dst, rws)
        set_requests_state(request_ids=[rws.request_id, ], new_state=RequestState.QUEUED, session=session)
        created_requests.append(rws.request_id)

    if not creation_successful:
        # Need to fail all the intermediate requests
        logger(logging.WARNING, 'Multihop : A request already exists for the transfer between %s and %s. Will cancel all the parent requests', transfer_path[0].src, transfer_path[-1].dst)
        try:
            set_requests_state(request_ids=created_requests, new_state=RequestState.FAILED, session=session)
        except UnsupportedOperation:
            logger(logging.ERROR, 'Multihop : Cannot cancel all the parent requests : %s', str(created_requests))

    return creation_successful


@read_session
def __list_transfer_requests_and_source_replicas(
    total_workers=0,
    worker_number=0,
    limit=None,
    activity=None,
    older_than=None,
    rses=None,
    request_type=RequestType.TRANSFER,
    request_state=None,
    transfertool=None,
    session=None,
) -> "List[RequestWithSources]":
    """
    List requests with source replicas
    :param total_workers:    Number of total workers.
    :param worker_number:    Id of the executing worker.
    :param limit:            Integer of requests to retrieve.
    :param activity:         Activity to be selected.
    :param older_than:       Only select requests older than this DateTime.
    :param rses:             List of rse_id to select requests.
    :param request_type:     Filter on the given request type.
    :param request_state:    Filter on the given request state
    :param transfertool:     The transfer tool as specified in rucio.cfg.
    :param session:          Database session to use.
    :returns:                List of RequestWithSources objects.
    """

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
                                 models.Request.created_at) \
        .with_hint(models.Request, "INDEX(REQUESTS REQUESTS_TYP_STA_UPD_IDX)", 'oracle') \
        .filter(models.Request.state == request_state) \
        .filter(models.Request.request_type == request_type) \
        .join(models.RSE, models.RSE.id == models.Request.dest_rse_id) \
        .filter(models.RSE.deleted == false()) \
        .order_by(models.Request.created_at) \
        .filter(models.RSE.availability.in_((2, 3, 6, 7)))

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

    sub_requests = filter_thread_work(session=session, query=sub_requests, total_threads=total_workers, thread_id=worker_number, hash_variable='requests.id')

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
         source_rse_id, source_rse_name, file_path, source_ranking, source_url, distance_ranking) in query:

        # rses (of unknown length) should be a temporary table to check against instead of this special case
        if rses and dest_rse_id not in rses:
            continue

        request = requests_by_id.get(request_id)
        if not request:
            request = RequestWithSources(id=request_id, request_type=request_type, rule_id=rule_id, scope=scope, name=name,
                                         md5=md5, adler32=adler32, byte_count=byte_count, activity=activity, attributes=attributes,
                                         previous_attempt_id=previous_attempt_id, dest_rse_data=RseData(id=dest_rse_id),
                                         account=account, retry_count=retry_count)
            requests_by_id[request_id] = request

        if source_rse_id is not None:
            request.sources.append(TransferSource(rse_data=RseData(id=source_rse_id, name=source_rse_name), file_path=file_path,
                                                  source_ranking=source_ranking, distance_ranking=distance_ranking, url=source_url))
    return list(requests_by_id.values())


@transactional_session
def __set_transfer_state(external_host, transfer_id, new_state, session=None):
    """
    Update the state of a transfer. Fails silently if the transfer_id does not exist.
    :param external_host:  Selected external host as string in format protocol://fqdn:port
    :param transfer_id:    External transfer job id as a string.
    :param new_state:      New state as string.
    :param session:        Database session to use.
    """

    record_counter('core.request.set_transfer_state')

    try:
        rowcount = session.query(models.Request).filter_by(external_id=transfer_id).update({'state': new_state, 'updated_at': datetime.datetime.utcnow()}, synchronize_session=False)
    except IntegrityError as error:
        raise RucioException(error.args)

    if not rowcount:
        raise UnsupportedOperation("Transfer %s on %s state %s cannot be updated." % (transfer_id, external_host, new_state))


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
