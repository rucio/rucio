# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2017
# - Cedric Serfon <cedric.serfon@cern.ch>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Patrick Austin, <patrick.austin@stfc.ac.uk>, 2020
# - Eli Chadwick, <eli.chadwick@stfc.ac.uk>, 2020
# - Thomas Beermann <thomas.beermann@cern.ch>, 2021
#
# PY3K COMPATIBLE

"""
The core staging.py is specifically for handling staging-requests, thus requests
where the external_id is already known.
Requests accessed by request_id  are covered in the core request.py
"""
import json
import logging
import traceback

from rucio.common.exception import InvalidRSEExpression
from rucio.common.rse_attributes import get_rse_attributes
from rucio.core import request
from rucio.core.rse import get_rse_name
from rucio.core.rse_expression_parser import parse_expression
from rucio.db.sqla.constants import RequestType
from rucio.db.sqla.session import read_session
from rucio.rse import rsemanager as rsemgr


@read_session
def get_stagein_requests_and_source_replicas(total_workers=0, worker_number=0, failover_schemes=None, limit=None, activity=None, older_than=None,
                                             rses=None, mock=False, schemes=None, bring_online=43200, retry_other_fts=False, session=None, logger=logging.log):
    """
    Get staging requests and the associated source replicas

    :param total_workers:         Number of total workers.
    :param worker_number:         Id of the executing worker.
    :param failover_schemes:      Failover schemes.
    :param limit:                 Limit.
    :param activity:              Activity.
    :param older_than:            Get transfers older than.
    :param rses:                  Include RSES.
    :param mock:                  Mock testing.
    :param schemes:               Include schemes.
    :param bring_online:          Bring online timeout.
    :parm retry_other_fts:        Retry other fts servers.
    :param logger:                Optional decorated logger that can be passed from the calling daemons or servers.
    :session:                     The database session in use.
    :returns:                     transfers, reqs_no_source, reqs_scheme_mismatch, reqs_only_tape_source
    """

    req_sources = request.list_stagein_requests_and_source_replicas(total_workers=total_workers,
                                                                    worker_number=worker_number,
                                                                    limit=limit,
                                                                    activity=activity,
                                                                    older_than=older_than,
                                                                    rses=rses,
                                                                    session=session)

    transfers, rses_info, protocols, rse_attrs, reqs_no_source = {}, {}, {}, {}, []
    for req_id, rule_id, scope, name, md5, adler32, bytes, activity, attributes, dest_rse_id, source_rse_id, rse, deterministic, rse_type, path, staging_buffer, retry_count, previous_attempt_id, src_url, ranking in req_sources:
        try:
            if rses and dest_rse_id not in rses:
                continue

            current_schemes = schemes
            if previous_attempt_id and failover_schemes:
                current_schemes = failover_schemes

            if req_id not in transfers:
                if req_id not in reqs_no_source:
                    reqs_no_source.append(req_id)

                if not src_url:
                    # source_rse_id will be None if no source replicas
                    # rse will be None if rse is staging area
                    # staging_buffer will be None if rse has no key 'staging_buffer'
                    if source_rse_id is None or rse is None or staging_buffer is None:
                        continue

                    # Get destination rse information and protocol
                    dest_rse_name = get_rse_name(rse_id=dest_rse_id, session=session)
                    if dest_rse_id not in rses_info:
                        rses_info[dest_rse_id] = rsemgr.get_rse_info(rse_id=dest_rse_id, session=session)

                    if staging_buffer != dest_rse_id:
                        continue

                    attr = None
                    if attributes:
                        if isinstance(attributes, dict):
                            attr = json.loads(json.dumps(attributes))
                        else:
                            attr = json.loads(str(attributes))

                    source_replica_expression = attr["source_replica_expression"] if "source_replica_expression" in attr else None
                    if source_replica_expression:
                        try:
                            parsed_rses = parse_expression(source_replica_expression, filter={'vo': scope.vo}, session=session)
                        except InvalidRSEExpression as error:
                            logger(logging.ERROR, "Invalid RSE exception %s: %s" % (source_replica_expression, error))
                            continue
                        else:
                            allowed_rses = [x['id'] for x in parsed_rses]
                            if source_rse_id not in allowed_rses:
                                continue

                    source_rse_name = get_rse_name(rse_id=source_rse_id, session=session)
                    if source_rse_id not in rses_info:
                        rses_info[source_rse_id] = rsemgr.get_rse_info(rse_id=source_rse_id, session=session)
                    if source_rse_id not in rse_attrs:
                        rse_attrs[source_rse_id] = get_rse_attributes(rse_id=source_rse_id, session=session)

                    if source_rse_id not in protocols:
                        protocols[source_rse_id] = rsemgr.create_protocol(rses_info[source_rse_id], 'write', current_schemes)

                    # we need to set the spacetoken if we use SRM
                    dest_spacetoken = None
                    if protocols[source_rse_id].attributes and \
                       'extended_attributes' in protocols[source_rse_id].attributes and \
                       protocols[source_rse_id].attributes['extended_attributes'] and \
                       'space_token' in protocols[source_rse_id].attributes['extended_attributes']:
                        dest_spacetoken = protocols[source_rse_id].attributes['extended_attributes']['space_token']

                    source_url = protocols[source_rse_id].lfns2pfns(lfns={'scope': scope.external, 'name': name, 'path': path}).values()[0]
                else:
                    # source_rse_id will be None if no source replicas
                    # rse will be None if rse is staging area
                    # staging_buffer will be None if rse has no key 'staging_buffer'
                    if source_rse_id is None or rse is None or staging_buffer is None:
                        continue

                    attr = None
                    if attributes:
                        if type(attributes) is dict:
                            attr = json.loads(json.dumps(attributes))
                        else:
                            attr = json.loads(str(attributes))

                    # to get space token and fts attribute
                    source_rse_name = get_rse_name(rse_id=source_rse_id, session=session)
                    if source_rse_id not in rses_info:
                        rses_info[source_rse_id] = rsemgr.get_rse_info(rse_id=source_rse_id, session=session)
                    if source_rse_id not in rse_attrs:
                        rse_attrs[source_rse_id] = get_rse_attributes(rse_id=source_rse_id, session=session)

                    if source_rse_id not in protocols:
                        protocols[source_rse_id] = rsemgr.create_protocol(rses_info[source_rse_id], 'write', current_schemes)

                    # we need to set the spacetoken if we use SRM
                    dest_spacetoken = None
                    if protocols[source_rse_id].attributes and \
                       'extended_attributes' in protocols[source_rse_id].attributes and \
                       protocols[source_rse_id].attributes['extended_attributes'] and \
                       'space_token' in protocols[source_rse_id].attributes['extended_attributes']:
                        dest_spacetoken = protocols[source_rse_id].attributes['extended_attributes']['space_token']
                    source_url = src_url

                fts_hosts = rse_attrs[source_rse_id].get('fts', None)
                if not fts_hosts:
                    logger(logging.ERROR, 'Source RSE %s FTS attribute not defined - SKIP REQUEST %s' % (rse, req_id))
                    continue
                if not retry_count:
                    retry_count = 0
                fts_list = fts_hosts.split(",")

                external_host = fts_list[0]
                if retry_other_fts:
                    external_host = fts_list[retry_count % len(fts_list)]

                if req_id in reqs_no_source:
                    reqs_no_source.remove(req_id)

                file_metadata = {'request_id': req_id,
                                 'scope': scope,
                                 'name': name,
                                 'activity': activity,
                                 'request_type': str(RequestType.STAGEIN).lower(),
                                 'src_type': "TAPE",
                                 'dst_type': "DISK",
                                 'src_rse': source_rse_name,
                                 'dst_rse': dest_rse_name,
                                 'src_rse_id': source_rse_id,
                                 'dest_rse_id': dest_rse_id,
                                 'filesize': bytes,
                                 'md5': md5,
                                 'adler32': adler32}
                if previous_attempt_id:
                    file_metadata['previous_attempt_id'] = previous_attempt_id

                transfers[req_id] = {'request_id': req_id,
                                     # 'src_urls': [source_url],
                                     'sources': [(rse, source_url, source_rse_id, ranking)],
                                     'dest_urls': [source_url],
                                     'src_spacetoken': None,
                                     'dest_spacetoken': dest_spacetoken,
                                     'overwrite': False,
                                     'bring_online': bring_online,
                                     'copy_pin_lifetime': attr.get('lifetime', -1) if attr else -1,
                                     'external_host': external_host,
                                     'selection_strategy': 'auto',
                                     'rule_id': rule_id,
                                     'file_metadata': file_metadata}
                logger(logging.DEBUG, "Transfer for request(%s): %s" % (req_id, transfers[req_id]))
        except Exception:
            logger(logging.CRITICAL, "Exception happened when trying to get transfer for request %s: %s" % (req_id, traceback.format_exc()))
            break

    return transfers, reqs_no_source
