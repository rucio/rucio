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
import json
import logging
import traceback
from collections import namedtuple
from typing import TYPE_CHECKING

from sqlalchemy import and_, or_, update, select, delete, exists
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import aliased
from sqlalchemy.sql.expression import asc, true, false, null, func

from rucio.common.config import config_get_bool
from rucio.common.exception import RequestNotFound, RucioException, UnsupportedOperation
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid, chunks
from rucio.core.message import add_message, add_messages
from rucio.core.monitor import record_counter, record_timer
from rucio.core.rse import get_rse_name, get_rse_vo, RseData
from rucio.db.sqla import models, filter_thread_work
from rucio.db.sqla.constants import RequestState, RequestType, LockState, RequestErrMsg, ReplicaState
from rucio.db.sqla.session import read_session, transactional_session, stream_session
from rucio.db.sqla.util import temp_table_mngr

RequestAndState = namedtuple('RequestAndState', ['request_id', 'request_state'])

if TYPE_CHECKING:
    from typing import Any, Dict, List, Optional, Sequence, Union

    from sqlalchemy.orm import Session

"""
The core request.py is specifically for handling requests.
Requests accessed by external_id (So called transfers), are covered in the core transfer.py
"""


class RequestSource:
    def __init__(self, rse_data, source_ranking=None, distance_ranking=None, file_path=None, scheme=None, url=None):
        self.rse = rse_data
        self.distance_ranking = distance_ranking if distance_ranking is not None else 9999
        self.source_ranking = source_ranking if source_ranking is not None else 0
        self.file_path = file_path
        self.scheme = scheme
        self.url = url

    def __str__(self):
        return "src_rse={}".format(self.rse)


class RequestWithSources:
    def __init__(
            self,
            id_: "Optional[str]",
            request_type: RequestType,
            rule_id: "Optional[str]",
            scope: InternalScope,
            name: str,
            md5: str,
            adler32: str,
            byte_count: int,
            activity: str,
            attributes: "Union[str, None, Dict[str, Any]]",
            previous_attempt_id: "Optional[str]",
            dest_rse_data: RseData,
            account: InternalAccount,
            retry_count: int,
            priority: int,
            transfertool: str,
            requested_at: "Optional[datetime.datetime]" = None,
    ):

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

        self.sources: "List[RequestSource]" = []
        self.requested_source: "Optional[RequestSource]" = None

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


def should_retry_request(req, retry_protocol_mismatches):
    """
    Whether should retry this request.

    :param request:                      Request as a dictionary.
    :param retry_protocol_mismatches:    Boolean to retry the transfer in case of protocol mismatch.
    :returns:                            True if should retry it; False if no more retry.
    """
    if is_intermediate_hop(req):
        # This is an intermediate request in a multi-hop transfer. It must not be re-scheduled on its own.
        # If needed, it will be re-scheduled via the creation of a new multi-hop transfer.
        return False
    if req['state'] == RequestState.SUBMITTING:
        return True
    if req['state'] == RequestState.NO_SOURCES or req['state'] == RequestState.ONLY_TAPE_SOURCES:
        return False
    # hardcoded for now - only requeue a couple of times
    if req['retry_count'] is None or req['retry_count'] < 3:
        if req['state'] == RequestState.MISMATCH_SCHEME:
            return retry_protocol_mismatches
        return True
    return False


@transactional_session
def requeue_and_archive(request, source_ranking_update=True, retry_protocol_mismatches=False, session=None, logger=logging.log):
    """
    Requeue and archive a failed request.
    TODO: Multiple requeue.

    :param request:               Original request.
    :param source_ranking_update  Boolean. If True, the source ranking is decreased (making the sources less likely to be used)
    :param session:               Database session to use.
    :param logger:                Optional decorated logger that can be passed from the calling daemons or servers.
    """

    record_counter('core.request.requeue_request')
    # Probably not needed anymore
    request_id = request['request_id']
    new_req = get_request(request_id, session=session)

    if new_req:
        new_req['sources'] = get_sources(request_id, session=session)
        archive_request(request_id, session=session)

        if should_retry_request(new_req, retry_protocol_mismatches):
            new_req['request_id'] = generate_uuid()
            new_req['previous_attempt_id'] = request_id
            if new_req['retry_count'] is None:
                new_req['retry_count'] = 1
            elif new_req['state'] != RequestState.SUBMITTING:
                new_req['retry_count'] += 1

            if source_ranking_update and new_req['sources']:
                for i in range(len(new_req['sources'])):
                    if new_req['sources'][i]['is_using']:
                        if new_req['sources'][i]['ranking'] is None:
                            new_req['sources'][i]['ranking'] = -1
                        else:
                            new_req['sources'][i]['ranking'] -= 1
                        new_req['sources'][i]['is_using'] = False
            new_req.pop('state', None)
            queue_requests([new_req], session=session, logger=logger)
            return new_req
    else:
        raise RequestNotFound
    return None


@transactional_session
def queue_requests(requests, session=None, logger=logging.log):
    """
    Submit transfer requests on destination RSEs for data identifiers.

    :param requests:  List of dictionaries containing request metadata.
    :param session:   Database session to use.
    :param logger:    Optional decorated logger that can be passed from the calling daemons or servers.
    :returns:         List of Request-IDs as 32 character hex strings.
    """
    record_counter('core.request.queue_requests')

    logger(logging.DEBUG, "queue requests")

    request_clause = []
    rses = {}
    preparer_enabled = config_get_bool('conveyor', 'use_preparer', raise_exception=False, default=False)
    for req in requests:

        if isinstance(req['attributes'], str):
            req['attributes'] = json.loads(req['attributes'] or '{}')
            if isinstance(req['attributes'], str):
                req['attributes'] = json.loads(req['attributes'] or '{}')

        if req['request_type'] == RequestType.TRANSFER:
            request_clause.append(and_(models.Request.scope == req['scope'],
                                       models.Request.name == req['name'],
                                       models.Request.dest_rse_id == req['dest_rse_id'],
                                       models.Request.request_type == RequestType.TRANSFER))

        if req['dest_rse_id'] not in rses:
            rses[req['dest_rse_id']] = get_rse_name(req['dest_rse_id'], session=session)

    # Check existing requests
    existing_requests = []
    if request_clause:
        for requests_condition in chunks(request_clause, 1000):
            stmt = select(
                models.Request.scope,
                models.Request.name,
                models.Request.dest_rse_id
            ).with_hint(
                models.Request, "INDEX(REQUESTS REQUESTS_SC_NA_RS_TY_UQ_IDX)", 'oracle'
            ).where(
                or_(*requests_condition)
            )
            existing_requests.extend(session.execute(stmt))

    new_requests, sources, messages = [], [], []
    for request in requests:
        dest_rse_name = get_rse_name(rse_id=request['dest_rse_id'], session=session)
        if request['request_type'] == RequestType.TRANSFER and (request['scope'], request['name'], request['dest_rse_id']) in existing_requests:
            logger(logging.WARNING, 'Request TYPE %s for DID %s:%s at RSE %s exists - ignoring' % (request['request_type'],
                                                                                                   request['scope'],
                                                                                                   request['name'],
                                                                                                   dest_rse_name))
            continue

        def temp_serializer(obj):
            if isinstance(obj, (InternalAccount, InternalScope)):
                return obj.internal
            raise TypeError('Could not serialise object %r' % obj)

        if 'state' not in request:
            request['state'] = RequestState.PREPARING if preparer_enabled else RequestState.QUEUED

        new_request = {'request_type': request['request_type'],
                       'scope': request['scope'],
                       'name': request['name'],
                       'dest_rse_id': request['dest_rse_id'],
                       'source_rse_id': request.get('source_rse_id', None),
                       'attributes': json.dumps(request['attributes'], default=temp_serializer),
                       'state': request['state'],
                       'rule_id': request['rule_id'],
                       'activity': request['attributes']['activity'],
                       'bytes': request['attributes']['bytes'],
                       'md5': request['attributes']['md5'],
                       'adler32': request['attributes']['adler32'],
                       'account': request.get('account', None),
                       'priority': request['attributes'].get('priority', None),
                       'requested_at': request.get('requested_at', None),
                       'retry_count': request['retry_count']}
        if 'transfertool' in request:
            new_request['transfertool'] = request['transfertool']
        if 'previous_attempt_id' in request and 'retry_count' in request:
            new_request['previous_attempt_id'] = request['previous_attempt_id']
            new_request['id'] = request['request_id']
        else:
            new_request['id'] = generate_uuid()
        new_requests.append(new_request)

        if 'sources' in request and request['sources']:
            for source in request['sources']:
                sources.append({'request_id': new_request['id'],
                                'scope': request['scope'],
                                'name': request['name'],
                                'rse_id': source['rse_id'],
                                'dest_rse_id': request['dest_rse_id'],
                                'ranking': source['ranking'],
                                'bytes': source['bytes'],
                                'url': source['url'],
                                'is_using': source['is_using']})

        if request['request_type']:
            transfer_status = '%s-%s' % (request['request_type'].name, request['state'].name)
        else:
            transfer_status = 'transfer-%s' % request['state'].name
        transfer_status = transfer_status.lower()

        payload = {'request-id': new_request['id'],
                   'request-type': request['request_type'].name.lower(),
                   'scope': request['scope'].external,
                   'name': request['name'],
                   'dst-rse-id': request['dest_rse_id'],
                   'dst-rse': dest_rse_name,
                   'state': request['state'].name.lower(),
                   'retry-count': request['retry_count'],
                   'rule-id': str(request['rule_id']),
                   'activity': request['attributes']['activity'],
                   'file-size': request['attributes']['bytes'],
                   'bytes': request['attributes']['bytes'],
                   'checksum-md5': request['attributes']['md5'],
                   'checksum-adler': request['attributes']['adler32'],
                   'queued_at': str(datetime.datetime.utcnow())}

        messages.append({'event_type': transfer_status,
                         'payload': payload})

    for requests_chunk in chunks(new_requests, 1000):
        session.bulk_insert_mappings(models.Request, requests_chunk)

    for sources_chunk in chunks(sources, 1000):
        session.bulk_insert_mappings(models.Source, sources_chunk)

    add_messages(messages, session=session)

    return new_requests


@read_session
def list_transfer_requests_and_source_replicas(
        total_workers: int = 0,
        worker_number: int = 0,
        partition_hash_var: "Optional[str]" = None,
        limit: "Optional[int]" = None,
        activity: "Optional[str]" = None,
        older_than: "Optional[datetime.datetime]" = None,
        rses: "Optional[Sequence[str]]" = None,
        request_type: "Optional[List[RequestType]]" = None,
        request_state: "Optional[RequestState]" = None,
        required_source_rse_attrs: "Optional[List[str]]" = None,
        ignore_availability: bool = False,
        transfertool: "Optional[str]" = None,
        session: "Optional[Session]" = None,
) -> "Dict[str, RequestWithSources]":
    """
    List requests with source replicas
    :param total_workers: Number of total workers.
    :param worker_number: Id of the executing worker.
    :param partition_hash_var: The hash variable used for partitioning thread work
    :param limit: Integer of requests to retrieve.
    :param activity: Activity to be selected.
    :param older_than: Only select requests older than this DateTime.
    :param rses: List of rse_id to select requests.
    :param request_type: Filter on the given request type.
    :param request_state: Filter on the given request state
    :param transfertool: The transfer tool as specified in rucio.cfg.
    :param required_source_rse_attrs: Only select source RSEs having these attributes set
    :param ignore_availability: Ignore blocklisted RSEs
    :param session: Database session to use.
    :returns: List of RequestWithSources objects.
    """

    if partition_hash_var is None:
        partition_hash_var = 'requests.id'

    if request_state is None:
        request_state = RequestState.QUEUED

    if request_type is None:
        request_type = [RequestType.TRANSFER]

    sub_requests = select(
        models.Request.id,
        models.Request.request_type,
        models.Request.rule_id,
        models.Request.scope,
        models.Request.name,
        models.Request.md5,
        models.Request.adler32,
        models.Request.bytes,
        models.Request.activity,
        models.Request.attributes,
        models.Request.previous_attempt_id,
        models.Request.source_rse_id,
        models.Request.dest_rse_id,
        models.Request.retry_count,
        models.Request.account,
        models.Request.created_at,
        models.Request.requested_at,
        models.Request.priority,
        models.Request.transfertool
    ).with_hint(
        models.Request, "INDEX(REQUESTS REQUESTS_TYP_STA_UPD_IDX)", 'oracle'
    ).where(
        models.Request.state == request_state,
        models.Request.request_type.in_(request_type)
    ).join(
        models.RSE,
        models.RSE.id == models.Request.dest_rse_id
    ).where(
        models.RSE.deleted == false()
    ).outerjoin(
        models.TransferHop,
        models.TransferHop.next_hop_request_id == models.Request.id
    ).where(
        models.TransferHop.next_hop_request_id == null()
    ).order_by(
        models.Request.created_at
    )

    if not ignore_availability:
        sub_requests = sub_requests.where(models.RSE.availability.in_((2, 3, 6, 7)))

    if isinstance(older_than, datetime.datetime):
        sub_requests = sub_requests.where(models.Request.requested_at < older_than)

    if activity:
        sub_requests = sub_requests.where(models.Request.activity == activity)

    # if a transfertool is specified make sure to filter for those requests and apply related index
    if transfertool:
        sub_requests = sub_requests.where(models.Request.transfertool == transfertool)
        sub_requests = sub_requests.with_hint(models.Request, "INDEX(REQUESTS REQUESTS_TYP_STA_TRA_ACT_IDX)", 'oracle')
    else:
        sub_requests = sub_requests.with_hint(models.Request, "INDEX(REQUESTS REQUESTS_TYP_STA_UPD_IDX)", 'oracle')

    use_temp_tables = config_get_bool('core', 'use_temp_tables', default=False, session=session)
    if rses and use_temp_tables:
        temp_table_cls = temp_table_mngr(session).create_id_table()

        session.bulk_insert_mappings(temp_table_cls, [{'id': rse_id} for rse_id in rses])

        sub_requests = sub_requests.join(temp_table_cls, temp_table_cls.id == models.RSE.id)

    sub_requests = filter_thread_work(session=session, query=sub_requests, total_threads=total_workers, thread_id=worker_number, hash_variable=partition_hash_var)

    if limit:
        sub_requests = sub_requests.limit(limit)

    sub_requests = sub_requests.subquery()

    stmt = select(
        sub_requests.c.id,
        sub_requests.c.request_type,
        sub_requests.c.rule_id,
        sub_requests.c.scope,
        sub_requests.c.name,
        sub_requests.c.md5,
        sub_requests.c.adler32,
        sub_requests.c.bytes,
        sub_requests.c.activity,
        sub_requests.c.attributes,
        sub_requests.c.previous_attempt_id,
        sub_requests.c.source_rse_id,
        sub_requests.c.dest_rse_id,
        sub_requests.c.account,
        sub_requests.c.retry_count,
        sub_requests.c.priority,
        sub_requests.c.transfertool,
        sub_requests.c.requested_at,
        models.RSE.id.label("replica_rse_id"),
        models.RSE.rse.label("replica_rse_name"),
        models.RSEFileAssociation.path,
        models.Source.ranking.label("source_ranking"),
        models.Source.url.label("source_url"),
        models.Distance.ranking.label("distance_ranking")
    ).order_by(
        sub_requests.c.created_at
    ).outerjoin(
        models.RSEFileAssociation,
        and_(sub_requests.c.scope == models.RSEFileAssociation.scope,
             sub_requests.c.name == models.RSEFileAssociation.name,
             models.RSEFileAssociation.state == ReplicaState.AVAILABLE,
             sub_requests.c.dest_rse_id != models.RSEFileAssociation.rse_id)
    ).with_hint(
        models.RSEFileAssociation, "INDEX(REPLICAS REPLICAS_PK)", 'oracle'
    ).outerjoin(
        models.RSE,
        and_(models.RSE.id == models.RSEFileAssociation.rse_id,
             models.RSE.deleted == false())
    ).outerjoin(
        models.Source,
        and_(sub_requests.c.id == models.Source.request_id,
             models.RSE.id == models.Source.rse_id)
    ).with_hint(
        models.Source, "INDEX(SOURCES SOURCES_PK)", 'oracle'
    ).outerjoin(
        models.Distance,
        and_(sub_requests.c.dest_rse_id == models.Distance.dest_rse_id,
             models.RSEFileAssociation.rse_id == models.Distance.src_rse_id)
    ).with_hint(
        models.Distance, "INDEX(DISTANCES DISTANCES_PK)", 'oracle'
    )

    for attribute in required_source_rse_attrs or ():
        rse_attr_alias = aliased(models.RSEAttrAssociation)
        stmt = stmt.where(
            exists(
                select(
                    [1]
                ).where(
                    rse_attr_alias.rse_id == models.RSE.id,
                    rse_attr_alias.key == attribute
                )
            )
        )

    requests_by_id = {}
    for (request_id, req_type, rule_id, scope, name, md5, adler32, byte_count, activity, attributes, previous_attempt_id, source_rse_id, dest_rse_id, account, retry_count,
         priority, transfertool, requested_at, replica_rse_id, replica_rse_name, file_path, source_ranking, source_url, distance_ranking) in session.execute(stmt):

        # If we didn't pre-filter using temporary tables on database side, perform the filtering here
        if not use_temp_tables and rses and dest_rse_id not in rses:
            continue

        request = requests_by_id.get(request_id)
        if not request:
            request = RequestWithSources(id_=request_id, request_type=req_type, rule_id=rule_id, scope=scope, name=name,
                                         md5=md5, adler32=adler32, byte_count=byte_count, activity=activity, attributes=attributes,
                                         previous_attempt_id=previous_attempt_id, dest_rse_data=RseData(id_=dest_rse_id),
                                         account=account, retry_count=retry_count, priority=priority, transfertool=transfertool,
                                         requested_at=requested_at)
            requests_by_id[request_id] = request

        if replica_rse_id is not None:
            source = RequestSource(rse_data=RseData(id_=replica_rse_id, name=replica_rse_name), file_path=file_path,
                                   source_ranking=source_ranking, distance_ranking=distance_ranking, url=source_url)
            request.sources.append(source)
            if source_rse_id == replica_rse_id:
                request.requested_source = source
    return requests_by_id


@read_session
def fetch_paths(request_id, session=None):
    """
    Find the paths for which the provided request is a constituent hop.

    Returns a dict: {initial_request_id1: path1, ...}. Each path is an ordered list of request_ids.
    """
    transfer_hop_alias = aliased(models.TransferHop)
    stmt = select(
        models.TransferHop,
    ).join(
        transfer_hop_alias,
        and_(
            transfer_hop_alias.initial_request_id == models.TransferHop.initial_request_id,
            or_(transfer_hop_alias.request_id == request_id,
                transfer_hop_alias.initial_request_id == request_id),
        )
    )

    parents_by_initial_request = {}
    for hop, in session.execute(stmt):
        parents_by_initial_request.setdefault(hop.initial_request_id, {})[hop.next_hop_request_id] = hop.request_id

    paths = {}
    for initial_request_id, parents in parents_by_initial_request.items():
        path = []
        cur_request = initial_request_id
        path.append(cur_request)
        while parents.get(cur_request):
            cur_request = parents[cur_request]
            path.append(cur_request)
        paths[initial_request_id] = list(reversed(path))
    return paths


@read_session
def get_next(request_type, state, limit=100, older_than=None, rse_id=None, activity=None,
             total_workers=0, worker_number=0, mode_all=False, hash_variable='id',
             activity_shares=None, include_dependent=True, transfertool=None, session=None):
    """
    Retrieve the next requests matching the request type and state.
    Workers are balanced via hashing to reduce concurrency on database.

    :param request_type:      Type of the request as a string or list of strings.
    :param state:             State of the request as a string or list of strings.
    :param limit:             Integer of requests to retrieve.
    :param older_than:        Only select requests older than this DateTime.
    :param rse_id:            The RSE to filter on.
    :param activity:          The activity to filter on.
    :param total_workers:     Number of total workers.
    :param worker_number:     Id of the executing worker.
    :param mode_all:          If set to True the function returns everything, if set to False returns list of dictionaries  {'request_id': x, 'external_host': y, 'external_id': z}.
    :param hash_variable:     The variable to use to perform the partitioning. By default it uses the request id.
    :param activity_shares:   Activity shares dictionary, with number of requests
    :param include_dependent: If true, includes transfers which have a previous hop dependency on other transfers
    :param transfertool:      The transfer tool as specified in rucio.cfg.
    :param session:           Database session to use.
    :returns:                 Request as a dictionary.
    """
    request_type_metric_label = '.'.join(a.name for a in request_type) if isinstance(request_type, list) else request_type.name
    state_metric_label = '.'.join(s.name for s in state) if isinstance(state, list) else state.name
    record_counter('core.request.get_next.{request_type}.{state}', labels={'request_type': request_type_metric_label,
                                                                           'state': state_metric_label})

    # lists of one element are not allowed by SQLA, so just duplicate the item
    if type(request_type) is not list:
        request_type = [request_type, request_type]
    elif len(request_type) == 1:
        request_type = [request_type[0], request_type[0]]
    if type(state) is not list:
        state = [state, state]
    elif len(state) == 1:
        state = [state[0], state[0]]

    result = []
    if not activity_shares:
        activity_shares = [None]

    for share in activity_shares:

        query = select(
            models.Request
        ).where(
            models.Request.state.in_(state),
            models.Request.request_type.in_(request_type)
        ).order_by(
            asc(models.Request.updated_at)
        )
        if transfertool:
            query = query.with_hint(
                models.Request, "INDEX(REQUESTS REQUESTS_TYP_STA_TRA_ACT_IDX)", 'oracle'
            ).where(
                models.Request.transfertool == transfertool
            )
        else:
            query = query.with_hint(
                models.Request, "INDEX(REQUESTS REQUESTS_TYP_STA_UPD_IDX)", 'oracle'
            )

        if not include_dependent:
            # filter out transfers which depend on some other "previous hop" requests.
            # In particular, this is used to avoid multiple finishers trying to archive different
            # transfers from the same path and thus having concurrent deletion of same rows from
            # the transfer_hop table.
            query = query.outerjoin(
                models.TransferHop,
                models.TransferHop.next_hop_request_id == models.Request.id
            ).where(
                models.TransferHop.next_hop_request_id == null()
            )

        if isinstance(older_than, datetime.datetime):
            query = query.filter(models.Request.updated_at < older_than)

        if rse_id:
            query = query.filter(models.Request.dest_rse_id == rse_id)

        if share:
            query = query.filter(models.Request.activity == share)
        elif activity:
            query = query.filter(models.Request.activity == activity)

        query = filter_thread_work(session=session, query=query, total_threads=total_workers, thread_id=worker_number, hash_variable=hash_variable)

        if share:
            query = query.limit(activity_shares[share])
        else:
            query = query.limit(limit)

        query_result = session.execute(query).scalars()
        if query_result:
            if mode_all:
                for res in query_result:
                    res_dict = dict(res)
                    res_dict.pop('_sa_instance_state')
                    res_dict['request_id'] = res_dict['id']
                    res_dict['attributes'] = json.loads(str(res_dict['attributes'] or '{}'))

                    dst_id = res_dict['dest_rse_id']
                    src_id = res_dict['source_rse_id']
                    res_dict['dest_rse'] = get_rse_name(rse_id=dst_id, session=session) if dst_id is not None else None
                    res_dict['source_rse'] = get_rse_name(rse_id=src_id, session=session) if src_id is not None else None

                    result.append(res_dict)
            else:
                for res in query_result:
                    result.append({'request_id': res.id, 'external_host': res.external_host, 'external_id': res.external_id})

    return result


@transactional_session
def set_request_state(request_id, state, external_id=None, transferred_at=None, started_at=None, staging_started_at=None,
                      staging_finished_at=None, source_rse_id=None, err_msg=None, attributes=None, session=None, logger=logging.log):
    """
    Update the state of a request.

    :param request_id:           Request-ID as a 32 character hex string.
    :param state:                New state as string.
    :param external_id:          External transfer job id as a string.
    :param transferred_at:       Transferred at timestamp
    :param started_at:           Started at timestamp
    :param staging_started_at:   Timestamp indicating the moment the stage beggins
    :param staging_finished_at:  Timestamp indicating the moment the stage ends
    :param logger:               Optional decorated logger that can be passed from the calling daemons or servers.
    :param session:              Database session to use.
    """

    # TODO: Should this be a private method?

    record_counter('core.request.set_request_state')

    rowcount = 0
    try:
        update_items = {'state': state, 'updated_at': datetime.datetime.utcnow()}
        if transferred_at:
            update_items['transferred_at'] = transferred_at
        if started_at:
            update_items['started_at'] = started_at
        if staging_started_at:
            update_items['staging_started_at'] = staging_started_at
        if staging_finished_at:
            update_items['staging_finished_at'] = staging_finished_at
        if source_rse_id:
            update_items['source_rse_id'] = source_rse_id
        if err_msg:
            update_items['err_msg'] = err_msg
        if attributes is not None:
            update_items['attributes'] = json.dumps(attributes)

        request = get_request(request_id, session=session)
        if not request:
            # The request was deleted in the meantime. Ignore it.
            logger(logging.WARNING, "Request %s not found. Cannot set its state to %s", request_id, state)
            return

        if state in [RequestState.FAILED, RequestState.DONE, RequestState.LOST] and (request["external_id"] != external_id):
            logger(logging.ERROR, "Request %s should not be updated to 'Failed' or 'Done' without external transfer_id" % request_id)
        else:
            stmt = update(
                models.Request
            ).where(
                models.Request.id == request_id
            ).execution_options(
                synchronize_session=False
            ).values(
                update_items
            )
            rowcount = session.execute(stmt).rowcount
    except IntegrityError as error:
        raise RucioException(error.args)

    if not rowcount:
        raise UnsupportedOperation("Request %s state cannot be updated." % request_id)


@transactional_session
def set_requests_state_if_possible(request_ids, new_state, session=None, logger=logging.log):
    """
    Bulk update the state of requests. Skips silently if the request_id does not exist.

    :param request_ids:  List of (Request-ID as a 32 character hex string).
    :param new_state:    New state as string.
    :param session:      Database session to use.
    :param logger:       Optional decorated logger that can be passed from the calling daemons or servers.
    """

    record_counter('core.request.set_requests_state_if_possible')

    try:
        for request_id in request_ids:
            try:
                set_request_state(request_id, new_state, session=session, logger=logger)
            except UnsupportedOperation:
                continue
    except IntegrityError as error:
        raise RucioException(error.args)


@transactional_session
def touch_requests_by_rule(rule_id, session=None):
    """
    Update the update time of requests in a rule. Fails silently if no requests on this rule.

    :param rule_id:  Rule-ID as a 32 character hex string.
    :param session:  Database session to use.
    """

    record_counter('core.request.touch_requests_by_rule')

    try:
        stmt = update(
            models.Request
        ).prefix_with(
            "/*+ INDEX(REQUESTS REQUESTS_RULEID_IDX) */", dialect='oracle'
        ).where(
            models.Request.rule_id == rule_id,
            models.Request.state.in_([RequestState.FAILED, RequestState.DONE, RequestState.LOST, RequestState.NO_SOURCES, RequestState.ONLY_TAPE_SOURCES]),
            models.Request.updated_at < datetime.datetime.utcnow()
        ).execution_options(
            synchronize_session=False
        ).values(
            updated_at=datetime.datetime.utcnow() + datetime.timedelta(minutes=20)
        )
        session.execute(stmt)
    except IntegrityError as error:
        raise RucioException(error.args)


@read_session
def get_request(request_id, session=None):
    """
    Retrieve a request by its ID.

    :param request_id:  Request-ID as a 32 character hex string.
    :param session:     Database session to use.
    :returns:           Request as a dictionary.
    """

    try:
        stmt = select(
            models.Request
        ).where(
            models.Request.id == request_id
        )
        tmp = session.execute(stmt).scalar()

        if not tmp:
            return
        else:
            tmp = dict(tmp)
            tmp.pop('_sa_instance_state')
            tmp['attributes'] = json.loads(str(tmp['attributes'] or '{}'))
            return tmp
    except IntegrityError as error:
        raise RucioException(error.args)


@read_session
def get_requests_by_transfer(external_host, transfer_id, session=None):
    """
    Retrieve requests by its transfer ID.

    :param request_host:  Name of the external host.
    :param transfer_id:   External transfer job id as a string.
    :param session:       Database session to use.
    :returns:             List of Requests.
    """

    try:
        stmt = select(
            models.Request
        ).where(
            models.Request.external_id == transfer_id
        )
        tmp = session.execute(stmt).scalars().all()

        if tmp:
            result = []
            for t in tmp:
                t2 = dict(t)
                t2.pop('_sa_instance_state')
                t2['request_id'] = t2['id']
                t2['attributes'] = json.loads(str(t2['attributes'] or '{}'))
                result.append(t2)
            return result
        return
    except IntegrityError as error:
        raise RucioException(error.args)


@read_session
def get_request_by_did(scope, name, rse_id, request_type=None, session=None):
    """
    Retrieve a request by its DID for a destination RSE.

    :param scope:          The scope of the data identifier.
    :param name:           The name of the data identifier.
    :param rse_id:         The destination RSE ID of the request.
    :param request_type:   The type of request as rucio.db.sqla.constants.RequestType.
    :param session:        Database session to use.
    :returns:              Request as a dictionary.
    """

    record_counter('core.request.get_request_by_did')
    try:
        stmt = select(
            models.Request
        ).where(
            models.Request.scope == scope,
            models.Request.name == name,
            models.Request.dest_rse_id == rse_id
        )
        if request_type:
            stmt = stmt.where(
                models.Request.request_type == request_type
            )

        tmp = session.execute(stmt).scalar()
        if not tmp:
            raise RequestNotFound(f'No request found for DID {scope}:{name} at RSE {rse_id}')
        else:
            tmp = dict(tmp)
            tmp.pop('_sa_instance_state')

            tmp['source_rse'] = get_rse_name(rse_id=tmp['source_rse_id'], session=session) if tmp['source_rse_id'] is not None else None
            tmp['dest_rse'] = get_rse_name(rse_id=tmp['dest_rse_id'], session=session) if tmp['dest_rse_id'] is not None else None
            tmp['attributes'] = json.loads(str(tmp['attributes'] or '{}'))

            return tmp
    except IntegrityError as error:
        raise RucioException(error.args)


@read_session
def get_request_history_by_did(scope, name, rse_id, request_type=None, session=None):
    """
    Retrieve a historical request by its DID for a destination RSE.

    :param scope:          The scope of the data identifier.
    :param name:           The name of the data identifier.
    :param rse_id:         The destination RSE ID of the request.
    :param request_type:   The type of request as rucio.db.sqla.constants.RequestType.
    :param session:        Database session to use.
    :returns:              Request as a dictionary.
    """

    record_counter('core.request.get_request_history_by_did')
    try:
        stmt = select(
            models.RequestHistory
        ).where(
            models.RequestHistory.scope == scope,
            models.RequestHistory.name == name,
            models.RequestHistory.dest_rse_id == rse_id
        )
        if request_type:
            stmt = stmt.where(
                models.RequestHistory.request_type == request_type
            )

        tmp = session.execute(stmt).scalar()
        if not tmp:
            raise RequestNotFound(f'No request found for DID {scope}:{name} at RSE {rse_id}')
        else:
            tmp = dict(tmp)
            tmp.pop('_sa_instance_state')

            tmp['source_rse'] = get_rse_name(rse_id=tmp['source_rse_id'], session=session) if tmp['source_rse_id'] is not None else None
            tmp['dest_rse'] = get_rse_name(rse_id=tmp['dest_rse_id'], session=session) if tmp['dest_rse_id'] is not None else None

            return tmp
    except IntegrityError as error:
        raise RucioException(error.args)


def is_intermediate_hop(request):
    """
    Check if the request is an intermediate hop in a multi-hop transfer.
    """
    if (request['attributes'] or {}).get('next_hop_request_id'):
        # This is only needed during the migration. When pre- 1.28 requests still exist
        # in the database and we have to handle them correctly.
        # TODO: remove this if
        return True
    if (request['attributes'] or {}).get('is_intermediate_hop'):
        return True
    return False


@transactional_session
def handle_failed_intermediate_hop(request, session=None):
    """
    Perform housekeeping behind a failed intermediate hop
    """
    # mark all hops following this one (in any multihop path) as Failed
    new_state = RequestState.FAILED
    reason = 'Unused hop in multi-hop'

    paths = fetch_paths(request['id'], session=session)
    dependent_requests = []
    for path in paths.values():
        idx = path.index(request['id'])
        dependent_requests.extend(path[idx + 1:])

    if dependent_requests:
        stmt = update(
            models.Request
        ).where(
            models.Request.id.in_(dependent_requests),
            models.Request.state.in_([RequestState.QUEUED, RequestState.SUBMITTED]),
        ).execution_options(
            synchronize_session=False
        ).values(
            state=new_state,
            err_msg=get_transfer_error(new_state, reason=reason),
        )
        session.execute(stmt)


@transactional_session
def archive_request(request_id, session=None):
    """
    Move a request to the history table.

    :param request_id:  Request-ID as a 32 character hex string.
    :param session:     Database session to use.
    """

    record_counter('core.request.archive')
    req = get_request(request_id=request_id, session=session)

    if req:
        hist_request = models.RequestHistory(id=req['id'],
                                             created_at=req['created_at'],
                                             request_type=req['request_type'],
                                             scope=req['scope'],
                                             name=req['name'],
                                             dest_rse_id=req['dest_rse_id'],
                                             source_rse_id=req['source_rse_id'],
                                             attributes=json.dumps(req['attributes']) if isinstance(req['attributes'], dict) else req['attributes'],
                                             state=req['state'],
                                             account=req['account'],
                                             external_id=req['external_id'],
                                             retry_count=req['retry_count'],
                                             err_msg=req['err_msg'],
                                             previous_attempt_id=req['previous_attempt_id'],
                                             external_host=req['external_host'],
                                             rule_id=req['rule_id'],
                                             activity=req['activity'],
                                             bytes=req['bytes'],
                                             md5=req['md5'],
                                             adler32=req['adler32'],
                                             dest_url=req['dest_url'],
                                             requested_at=req['requested_at'],
                                             submitted_at=req['submitted_at'],
                                             staging_started_at=req['staging_started_at'],
                                             staging_finished_at=req['staging_finished_at'],
                                             started_at=req['started_at'],
                                             estimated_started_at=req['estimated_started_at'],
                                             estimated_at=req['estimated_at'],
                                             transferred_at=req['transferred_at'],
                                             estimated_transferred_at=req['estimated_transferred_at'],
                                             transfertool=req['transfertool'])
        hist_request.save(session=session)
        try:
            time_diff = req['updated_at'] - req['created_at']
            time_diff_s = time_diff.seconds + time_diff.days * 24 * 3600
            record_timer('core.request.archive_request.{activity}', time_diff_s, labels={'activity': req['activity'].replace(' ', '_')})
            session.execute(
                delete(
                    models.Source
                ).where(
                    models.Source.request_id == request_id
                )
            )
            session.execute(
                delete(
                    models.TransferHop
                ).where(
                    or_(models.TransferHop.request_id == request_id,
                        models.TransferHop.next_hop_request_id == request_id,
                        models.TransferHop.initial_request_id == request_id)
                )
            )
            session.execute(
                delete(
                    models.Request
                ).where(
                    models.Request.id == request_id
                )
            )
        except IntegrityError as error:
            raise RucioException(error.args)


@transactional_session
def cancel_request_did(scope, name, dest_rse_id, request_type=RequestType.TRANSFER, session=None, logger=logging.log):
    """
    Cancel a request based on a DID and request type.

    :param scope:         Data identifier scope as a string.
    :param name:          Data identifier name as a string.
    :param dest_rse_id:   RSE id as a string.
    :param request_type:  Type of the request.
    :param session:       Database session to use.
    :param logger:        Optional decorated logger that can be passed from the calling daemons or servers.
    """

    record_counter('core.request.cancel_request_did')

    reqs = None
    try:
        stmt = select(
            models.Request.id,
            models.Request.external_id,
            models.Request.external_host
        ).where(
            models.Request.scope == scope,
            models.Request.name == name,
            models.Request.dest_rse_id == dest_rse_id,
            models.Request.request_type == request_type
        )
        reqs = session.execute(stmt).all()
        if not reqs:
            logger(logging.WARNING, 'Tried to cancel non-existant request for DID %s:%s at RSE %s' % (scope, name, get_rse_name(rse_id=dest_rse_id, session=session)))
    except IntegrityError as error:
        raise RucioException(error.args)

    transfers_to_cancel = {}
    for req in reqs:
        # is there a transfer already in transfertool? if so, schedule to cancel them
        if req[1] is not None:
            transfers_to_cancel.setdefault(req[2], set()).add(req[1])
        archive_request(request_id=req[0], session=session)
    return transfers_to_cancel


@read_session
def get_sources(request_id, rse_id=None, session=None):
    """
    Retrieve sources by its ID.

    :param request_id:  Request-ID as a 32 character hex string.
    :param rse_id:      RSE ID as a 32 character hex string.
    :param session:     Database session to use.
    :returns:           Sources as a dictionary.
    """

    try:
        stmt = select(
            models.Source
        ).where(
            models.Source.request_id == request_id
        )
        if rse_id:
            stmt = stmt.where(
                models.Source.rse_id == rse_id
            )
        tmp = session.execute(stmt).scalars().all()
        if not tmp:
            return
        else:
            result = []
            for t in tmp:
                t2 = dict(t)
                t2.pop('_sa_instance_state')
                result.append(t2)

            return result
    except IntegrityError as error:
        raise RucioException(error.args)


@read_session
def get_heavy_load_rses(threshold, session=None):
    """
    Retrieve heavy load rses.

    :param threshold:  Threshold as an int.
    :param session:    Database session to use.
    :returns: .
    """
    try:
        stmt = select(
            models.Source.rse_id,
            func.count(models.Source.rse_id).label('load')
        ).where(
            models.Source.is_using == true()
        ).group_by(
            models.Source.rse_id
        )
        results = session.execute(stmt).all()

        if not results:
            return

        result = []
        for t in results:
            if t[1] >= threshold:
                t2 = {'rse_id': t[0], 'load': t[1]}
                result.append(t2)

        return result
    except IntegrityError as error:
        raise RucioException(error.args)


@read_session
def get_request_stats(state, session=None):
    """
    Retrieve statistics about requests by destination, activity and state.

    :param state:           Request state.
    :param session:         Database session to use.
    :returns:               List of (activity, dest_rse_id, state, counter).
    """

    if type(state) is not list:
        state = [state]

    try:
        stmt = select(
            models.Request.account,
            models.Request.state,
            models.Request.dest_rse_id,
            models.Request.source_rse_id,
            models.Request.activity,
            func.count(1).label('counter'),
        ).with_hint(
            models.Request, "INDEX(REQUESTS REQUESTS_TYP_STA_UPD_IDX)", 'oracle'
        ).where(
            models.Request.state.in_(state),
            models.Request.request_type.in_([RequestType.TRANSFER, RequestType.STAGEIN, RequestType.STAGEOUT])
        ).group_by(
            models.Request.account,
            models.Request.state,
            models.Request.dest_rse_id,
            models.Request.source_rse_id,
            models.Request.activity,
        )

        return session.execute(stmt).all()

    except IntegrityError as error:
        raise RucioException(error.args)


@transactional_session
def release_waiting_requests_per_deadline(
        dest_rse_id: "Optional[str]" = None,
        source_rse_id: "Optional[str]" = None,
        deadline: int = 1,
        session=None,
):
    """
    Release waiting requests that were waiting too long and exceeded the maximum waiting time to be released.
    If the DID of a request is attached to a dataset, the oldest requested_at date of all requests related to the dataset will be used for checking and all requests of this dataset will be released.
    :param dest_rse_id: The destination RSE id.
    :param source_rse_id: The source RSE id.
    :param deadline: Maximal waiting time in hours until a dataset gets released.
    :param session: The database session.
    """
    amount_released_requests = 0
    if deadline:
        grouped_requests_subquery, filtered_requests_subquery = create_base_query_grouped_fifo(dest_rse_id=dest_rse_id, source_rse_id=source_rse_id, session=session)
        old_requests_subquery = select(
            grouped_requests_subquery.c.name,
            grouped_requests_subquery.c.scope,
            grouped_requests_subquery.c.oldest_requested_at
        ).where(
            grouped_requests_subquery.c.oldest_requested_at < datetime.datetime.now() - datetime.timedelta(hours=deadline)
        ).subquery()

        old_requests_subquery = select(
            filtered_requests_subquery.c.id
        ).join(
            old_requests_subquery,
            and_(filtered_requests_subquery.c.dataset_name == old_requests_subquery.c.name,
                 filtered_requests_subquery.c.dataset_scope == old_requests_subquery.c.scope)
        ).subquery()

        amount_released_requests = update(
            models.Request
        ).where(
            models.Request.id.in_(old_requests_subquery)
        ).execution_options(
            synchronize_session=False
        ).values(
            {models.Request.state: RequestState.QUEUED}
        )
    return session.execute(amount_released_requests).rowcount


@transactional_session
def release_waiting_requests_per_free_volume(
        dest_rse_id: "Optional[str]" = None,
        source_rse_id: "Optional[str]" = None,
        volume: int = 0,
        session=None
):
    """
    Release waiting requests if they fit in available transfer volume. If the DID of a request is attached to a dataset, the volume will be checked for the whole dataset as all requests related to this dataset will be released.

    :param dest_rse_id: The destination RSE id.
    :param source_rse_id: The source RSE id
    :param volume: The maximum volume in bytes that should be transfered.
    :param session: The database session.
    """

    dialect = session.bind.dialect.name
    if dialect == 'mysql' or dialect == 'sqlite':
        coalesce_func = func.ifnull
    elif dialect == 'oracle':
        coalesce_func = func.nvl
    else:  # dialect == 'postgresql'
        coalesce_func = func.coalesce

    sum_volume_active_subquery = select(
        coalesce_func(func.sum(models.Request.bytes), 0).label('sum_bytes')
    ).where(
        models.Request.state.in_([RequestState.SUBMITTED, RequestState.QUEUED]),
    )
    if dest_rse_id is not None:
        sum_volume_active_subquery = sum_volume_active_subquery.where(
            models.Request.dest_rse_id == dest_rse_id
        )
    if source_rse_id is not None:
        sum_volume_active_subquery = sum_volume_active_subquery.where(
            models.Request.source_rse_id == source_rse_id
        )
    sum_volume_active_subquery = sum_volume_active_subquery.subquery()

    grouped_requests_subquery, filtered_requests_subquery = create_base_query_grouped_fifo(dest_rse_id=dest_rse_id, source_rse_id=source_rse_id, session=session)

    cumulated_volume_subquery = select(
        grouped_requests_subquery.c.name,
        grouped_requests_subquery.c.scope,
        func.sum(grouped_requests_subquery.c.volume).over(order_by=grouped_requests_subquery.c.oldest_requested_at).label('cum_volume')
    ).where(
        grouped_requests_subquery.c.volume <= volume - sum_volume_active_subquery.c.sum_bytes
    ).subquery()

    cumulated_volume_subquery = select(
        filtered_requests_subquery.c.id
    ).join(
        cumulated_volume_subquery,
        and_(filtered_requests_subquery.c.dataset_name == cumulated_volume_subquery.c.name,
             filtered_requests_subquery.c.dataset_scope == cumulated_volume_subquery.c.scope)
    ).where(
        cumulated_volume_subquery.c.cum_volume <= volume - sum_volume_active_subquery.c.sum_bytes
    ).subquery()

    amount_released_requests = update(
        models.Request
    ).where(
        models.Request.id.in_(cumulated_volume_subquery)
    ).execution_options(
        synchronize_session=False
    ).values(
        {models.Request.state: RequestState.QUEUED},
    )
    return session.execute(amount_released_requests).rowcount


@read_session
def create_base_query_grouped_fifo(
        dest_rse_id: "Optional[str]" = None,
        source_rse_id: "Optional[str]" = None,
        session=None
):
    """
    Build the sqlalchemy queries to filter relevant requests and to group them in datasets.
    Group requests either by same destination RSE or source RSE.

    :param dest_rse_id: The source RSE id to filter on
    :param source_rse_id: The destination RSE id to filter on
    :param session: The database session.
    """
    dialect = session.bind.dialect.name
    if dialect == 'mysql' or dialect == 'sqlite':
        coalesce_func = func.ifnull
    elif dialect == 'oracle':
        coalesce_func = func.nvl
    else:  # dialect == 'postgresql'
        coalesce_func = func.coalesce

    # query DIDs that are attached to a collection and add a column indicating the order of attachment in case of mulitple attachments
    attachment_order_subquery = select(
        models.DataIdentifierAssociation.child_name,
        models.DataIdentifierAssociation.child_scope,
        models.DataIdentifierAssociation.name,
        models.DataIdentifierAssociation.scope,
        func.row_number().over(
            partition_by=(models.DataIdentifierAssociation.child_name,
                          models.DataIdentifierAssociation.child_scope),
            order_by=models.DataIdentifierAssociation.created_at
        ).label('order_of_attachment')
    ).subquery()

    # query transfer requests and join with according datasets
    requests_subquery_stmt = select(
        # Will be filled using add_columns() later
    ).outerjoin(
        attachment_order_subquery,
        and_(models.Request.name == attachment_order_subquery.c.child_name,
             models.Request.scope == attachment_order_subquery.c.child_scope,
             attachment_order_subquery.c.order_of_attachment == 1),
    ).where(
        models.Request.state == RequestState.WAITING,
    )
    if source_rse_id is not None:
        requests_subquery_stmt = requests_subquery_stmt.where(
            models.Request.source_rse_id == source_rse_id
        )
    if dest_rse_id is not None:
        requests_subquery_stmt = requests_subquery_stmt.where(
            models.Request.dest_rse_id == dest_rse_id
        )

    filtered_requests_subquery = requests_subquery_stmt.add_columns(
        coalesce_func(attachment_order_subquery.c.scope, models.Request.scope).label('dataset_scope'),
        coalesce_func(attachment_order_subquery.c.name, models.Request.name).label('dataset_name'),
        models.Request.id.label('id')
    ).subquery()

    combined_attached_unattached_requests = requests_subquery_stmt.add_columns(
        coalesce_func(attachment_order_subquery.c.scope, models.Request.scope).label('scope'),
        coalesce_func(attachment_order_subquery.c.name, models.Request.name).label('name'),
        models.Request.bytes,
        models.Request.requested_at
    ).subquery()

    # group requests and calculate properties like oldest requested_at, amount of children, volume
    grouped_requests_subquery = select(
        func.sum(combined_attached_unattached_requests.c.bytes).label('volume'),
        func.min(combined_attached_unattached_requests.c.requested_at).label('oldest_requested_at'),
        func.count().label('amount_childs'),
        combined_attached_unattached_requests.c.name,
        combined_attached_unattached_requests.c.scope
    ).group_by(
        combined_attached_unattached_requests.c.scope,
        combined_attached_unattached_requests.c.name
    ).subquery()
    return grouped_requests_subquery, filtered_requests_subquery


@transactional_session
def release_waiting_requests_fifo(
        dest_rse_id: "Optional[str]" = None,
        source_rse_id: "Optional[str]" = None,
        activity: "Optional[str]" = None,
        count: int = 0,
        account: "Optional[InternalAccount]" = None,
        session=None
):
    """
    Release waiting requests. Transfer requests that were requested first, get released first (FIFO).

    :param source_rse_id: The source rse id
    :param dest_rse_id: The destination rse id
    :param activity: The activity.
    :param count: The count to be released.
    :param account: The account name whose requests to release.
    :param session: The database session.
    """

    dialect = session.bind.dialect.name
    rowcount = 0

    subquery = select(
        models.Request.id
    ).where(
        models.Request.state == RequestState.WAITING
    ).order_by(
        asc(models.Request.requested_at)
    ).limit(
        count
    )
    if source_rse_id is not None:
        subquery = subquery.where(models.Request.source_rse_id == source_rse_id)
    if dest_rse_id is not None:
        subquery = subquery.where(models.Request.dest_rse_id == dest_rse_id)

    if activity is not None:
        subquery = subquery.where(models.Request.activity == activity)
    if account is not None:
        subquery = subquery.where(models.Request.account == account)

    subquery = subquery.subquery()

    if dialect == 'mysql':
        # TODO: check if the logic from this `if` is still needed on modern mysql

        # join because IN and LIMIT cannot be used together
        subquery = select(
            models.Request.id
        ).join(
            subquery,
            models.Request.id == subquery.c.id
        ).subquery()
        # wrap select to update and select from the same table
        subquery = select(subquery.c.id).subquery()

    stmt = update(
        models.Request
    ).where(
        models.Request.id.in_(subquery)
    ).execution_options(
        synchronize_session=False
    ).values(
        {'state': RequestState.QUEUED}
    )
    rowcount = session.execute(stmt).rowcount
    return rowcount


@transactional_session
def release_waiting_requests_grouped_fifo(
        dest_rse_id: "Optional[str]" = None,
        source_rse_id: "Optional[str]" = None,
        count: int = 0,
        deadline: int = 1,
        volume: int = 0,
        session=None
):
    """
    Release waiting requests. Transfer requests that were requested first, get released first (FIFO).
    Also all requests to DIDs that are attached to the same dataset get released, if one children of the dataset is choosed to be released (Grouped FIFO).

    :param dest_rse_id: The destination rse id
    :param source_rse_id: The source RSE id.
    :param count: The count to be released. If None, release all waiting requests.
    :param deadline: Maximal waiting time in hours until a dataset gets released.
    :param volume: The maximum volume in bytes that should be transfered.
    :param session: The database session.
    """

    amount_updated_requests = 0

    # Release requests that exceeded waiting time
    if deadline and source_rse_id is not None:
        amount_updated_requests = release_waiting_requests_per_deadline(dest_rse_id=dest_rse_id, source_rse_id=source_rse_id, deadline=deadline, session=session)
        count = count - amount_updated_requests

    grouped_requests_subquery, filtered_requests_subquery = create_base_query_grouped_fifo(dest_rse_id=dest_rse_id, source_rse_id=source_rse_id, session=session)

    # cumulate amount of children per dataset and combine with each request and only keep requests that dont exceed the limit
    cumulated_children_subquery = select(
        grouped_requests_subquery.c.name,
        grouped_requests_subquery.c.scope,
        grouped_requests_subquery.c.amount_childs,
        grouped_requests_subquery.c.oldest_requested_at,
        func.sum(grouped_requests_subquery.c.amount_childs).over(order_by=(grouped_requests_subquery.c.oldest_requested_at)).label('cum_amount_childs')
    ).subquery()
    cumulated_children_subquery = select(
        filtered_requests_subquery.c.id
    ).join(
        cumulated_children_subquery,
        and_(filtered_requests_subquery.c.dataset_name == cumulated_children_subquery.c.name,
             filtered_requests_subquery.c.dataset_scope == cumulated_children_subquery.c.scope)
    ).where(
        cumulated_children_subquery.c.cum_amount_childs - cumulated_children_subquery.c.amount_childs < count
    ).subquery()

    # needed for mysql to update and select from the same table
    cumulated_children_subquery = select(cumulated_children_subquery.c.id).subquery()

    stmt = update(
        models.Request
    ).where(
        models.Request.id.in_(cumulated_children_subquery)
    ).execution_options(
        synchronize_session=False
    ).values(
        {models.Request.state: RequestState.QUEUED}
    )
    amount_updated_requests += session.execute(stmt).rowcount

    # release requests where the whole datasets volume fits in the available volume space
    if volume and dest_rse_id is not None:
        amount_updated_requests += release_waiting_requests_per_free_volume(dest_rse_id=dest_rse_id, volume=volume, session=session)

    return amount_updated_requests


@transactional_session
def release_all_waiting_requests(
        dest_rse_id: "Optional[str]" = None,
        source_rse_id: "Optional[str]" = None,
        activity: "Optional[str]" = None,
        account: "Optional[InternalAccount]" = None,
        session=None
):
    """
    Release all waiting requests per destination RSE.

    :param dest_rse_id: The destination rse id.
    :param source_rse_id: The source rse id.
    :param activity: The activity.
    :param account: The account name whose requests to release.
    :param session: The database session.
    """
    try:
        query = update(
            models.Request
        ).where(
            models.Request.state == RequestState.WAITING,
        ).execution_options(
            synchronize_session=False
        ).values(
            {'state': RequestState.QUEUED}
        )
        if source_rse_id is not None:
            query = query.where(
                models.Request.source_rse_id == source_rse_id
            )
        if dest_rse_id is not None:
            query = query.where(
                models.Request.dest_rse_id == dest_rse_id
            )
        if activity is not None:
            query = query.where(
                models.Request.activity == activity
            )
        if account is not None:
            query = query.where(
                models.Request.account == account
            )
        rowcount = session.execute(query).rowcount
        return rowcount
    except IntegrityError as error:
        raise RucioException(error.args)


@transactional_session
def update_requests_priority(priority, filter_, session=None, logger=logging.log):
    """
    Update priority of requests.

    :param priority:  The priority as an integer from 1 to 5.
    :param filter_:    Dictionary such as {'rule_id': rule_id, 'request_id': request_id, 'older_than': time_stamp, 'activities': [activities]}.
    :param logger:    Optional decorated logger that can be passed from the calling daemons or servers.
    :return the transfers which must be updated in the transfertool
    """
    try:
        query = select(
            models.Request.id,
            models.Request.external_id,
            models.Request.external_host,
            models.Request.state.label('request_state'),
            models.ReplicaLock.state.label('lock_state')
        ).join(
            models.ReplicaLock,
            and_(models.ReplicaLock.scope == models.Request.scope,
                 models.ReplicaLock.name == models.Request.name,
                 models.ReplicaLock.rse_id == models.Request.dest_rse_id)
        )
        if 'rule_id' in filter_:
            query = query.filter(models.ReplicaLock.rule_id == filter_['rule_id'])
        if 'request_id' in filter_:
            query = query.filter(models.Request.id == filter_['request_id'])
        if 'older_than' in filter_:
            query = query.filter(models.Request.created_at < filter_['older_than'])
        if 'activities' in filter_:
            if type(filter_['activities']) is not list:
                filter_['activities'] = filter_['activities'].split(',')
            query = query.filter(models.Request.activity.in_(filter_['activities']))

        transfers_to_update = {}
        for item in session.execute(query).all():
            try:
                stmt = update(
                    models.Request
                ).where(
                    models.Request.id == item.id
                ).execution_options(
                    synchronize_session=False
                ).values(
                    {
                        'priority': priority,
                        'updated_at': datetime.datetime.utcnow(),
                    }
                )
                session.execute(stmt)
                logger(logging.DEBUG, "Updated request %s priority to %s in rucio." % (item.id, priority))
                if item.request_state == RequestState.SUBMITTED and item.lock_state == LockState.REPLICATING:
                    transfers_to_update.setdefault(item.external_host, {})[item.external_id] = priority
            except Exception:
                logger(logging.DEBUG, "Failed to boost request %s priority: %s" % (item.id, traceback.format_exc()))
        return transfers_to_update
    except IntegrityError as error:
        raise RucioException(error.args)


@transactional_session
def update_request_state(tt_status_report, session=None, logger=logging.log):
    """
    Used by poller and consumer to update the internal state of requests,
    after the response by the external transfertool.

    :param tt_status_report:      The transfertool status update, retrieved via request.query_request().
    :param session:               The database session to use.
    :param logger:                Optional decorated logger that can be passed from the calling daemons or servers.
    :returns commit_or_rollback:  Boolean.
    """

    request_id = tt_status_report.request_id
    try:
        fields_to_update = tt_status_report.get_db_fields_to_update(session=session, logger=logger)
        if not fields_to_update:
            __touch_request(request_id, session=session)
            return False
        else:
            logger(logging.INFO, 'UPDATING REQUEST %s FOR %s with changes: %s' % (str(request_id), tt_status_report, fields_to_update))

            set_request_state(request_id, session=session, **fields_to_update)
            request = tt_status_report.request(session)

            if tt_status_report.state == RequestState.FAILED:
                if is_intermediate_hop(request):
                    handle_failed_intermediate_hop(request, session=session)

            add_monitor_message(new_state=tt_status_report.state,
                                request=request,
                                additional_fields=tt_status_report.get_monitor_msg_fields(session=session, logger=logger),
                                session=session)
            return True
    except UnsupportedOperation as error:
        logger(logging.WARNING, "Request %s doesn't exist - Error: %s" % (request_id, str(error).replace('\n', '')))
        return False
    except Exception:
        logger(logging.CRITICAL, "Exception", exc_info=True)


@read_session
def add_monitor_message(new_state, request, additional_fields, session=None):
    """
    Create a message for hermes from a request

    :param new_state:         The new state of the transfer request
    :param request:           The request to create the message for.
    :param additional_fields: Additional custom fields to be added to the message
    :param session:           The database session to use.
    """

    if request['request_type']:
        transfer_status = '%s-%s' % (request['request_type'].name, new_state.name)
    else:
        transfer_status = 'transfer-%s' % new_state.name
    transfer_status = transfer_status.lower()

    stmt = select(
        models.DataIdentifier.datatype
    ).where(
        models.DataIdentifier.scope == request['scope'],
        models.DataIdentifier.name == request['name'],
    )
    datatype = session.execute(stmt).scalar_one_or_none()

    # Start by filling up fields from database request or with defaults.
    message = {'activity': request.get('activity', None),
               'request-id': request['id'],
               'duration': -1,
               'checksum-adler': request.get('adler32', None),
               'checksum-md5': request.get('md5', None),
               'file-size': request.get('bytes', None),
               'bytes': request.get('bytes', None),
               'guid': None,
               'previous-request-id': request['previous_attempt_id'],
               'protocol': None,
               'scope': request['scope'],
               'name': request['name'],
               'dataset': None,
               'datasetScope': None,
               'src-type': None,
               'src-rse': request.get('source_rse', None),
               'src-url': None,
               'dst-type': None,
               'dst-rse': request.get('dest_rse', None),
               'dst-url': request.get('dest_url', None),
               'reason': request.get('err_msg', None),
               'transfer-endpoint': request['external_host'],
               'transfer-id': request['external_id'],
               'transfer-link': None,
               'created_at': request.get('created_at', None),
               'submitted_at': request.get('submitted_at', None),
               'started_at': request.get('started_at', None),
               'transferred_at': request.get('transferred_at', None),
               'tool-id': 'rucio-conveyor',
               'account': request.get('account', None),
               'datatype': datatype}

    # Add (or override) existing fields
    message.update(additional_fields)

    if message['started_at'] and message['transferred_at']:
        message['duration'] = (message['transferred_at'] - message['started_at']).seconds
    ds_scope = request['attributes'].get('ds_scope')
    if not message['datasetScope'] and ds_scope:
        message['datasetScope'] = ds_scope
    ds_name = request['attributes'].get('ds_name')
    if not message['dataset'] and ds_name:
        message['dataset'] = ds_name
    if not message.get('protocol'):
        dst_url = message['dst-url']
        if dst_url and ':' in dst_url:
            message['protocol'] = dst_url.split(':')[0]
        elif request.get('transfertool'):
            message['protocol'] = request['transfertool']
    if not message.get('src-rse'):
        src_rse_id = request.get('source_rse_id', None)
        if src_rse_id:
            src_rse = get_rse_name(src_rse_id, session=session)
            message['src-rse'] = src_rse
    if not message.get('dst-rse'):
        dst_rse_id = request.get('dest_rse_id', None)
        if dst_rse_id:
            dst_rse = get_rse_name(dst_rse_id, session=session)
            message['dst-rse'] = dst_rse
    if not message.get('vo') and request.get('source_rse_id'):
        src_id = request['source_rse_id']
        vo = get_rse_vo(rse_id=src_id, session=session)
        if vo != 'def':
            message['vo'] = vo
    for time_field in ('created_at', 'submitted_at', 'started_at', 'transferred_at'):
        field_value = message[time_field]
        message[time_field] = str(field_value) if field_value else None

    add_message(transfer_status, message, session=session)


def get_transfer_error(state, reason=None):
    """
    Transform a specific RequestState to an error message

    :param state:   State of the request.
    :param reason:  Reason of the state.
    :returns:       Error message
    """
    err_msg = None
    if state in [RequestState.NO_SOURCES, RequestState.ONLY_TAPE_SOURCES]:
        err_msg = '%s:%s' % (RequestErrMsg.NO_SOURCES, state)
    elif state in [RequestState.SUBMISSION_FAILED]:
        err_msg = '%s:%s' % (RequestErrMsg.SUBMISSION_FAILED, state)
    elif state in [RequestState.SUBMITTING]:
        err_msg = '%s:%s' % (RequestErrMsg.SUBMISSION_FAILED, "Too long time in submitting state")
    elif state in [RequestState.LOST]:
        err_msg = '%s:%s' % (RequestErrMsg.TRANSFER_FAILED, "Transfer job on FTS is lost")
    elif state in [RequestState.FAILED]:
        err_msg = '%s:%s' % (RequestErrMsg.TRANSFER_FAILED, reason)
    elif state in [RequestState.MISMATCH_SCHEME]:
        err_msg = '%s:%s' % (RequestErrMsg.MISMATCH_SCHEME, state)
    return err_msg


@transactional_session
def __touch_request(request_id, session=None):
    """
    Update the timestamp of a request. Fails silently if the request_id does not exist.

    :param request_id:  Request-ID as a 32 character hex string.
    :param session:     Database session to use.
    """

    record_counter('core.request.touch_request')

    try:
        stmt = update(
            models.Request
        ).where(
            models.Request.id == request_id
        ).execution_options(
            synchronize_session=False
        ).values(
            {'updated_at': datetime.datetime.utcnow()}
        )
        rowcount = session.execute(stmt).rowcount
    except IntegrityError as error:
        raise RucioException(error.args)
    if not rowcount:
        raise UnsupportedOperation("Request %s cannot be touched." % request_id)


@read_session
def get_source_rse(request_id, src_url, session=None, logger=logging.log):
    """
    Based on a request, and src_url extract the source rse name and id.

    :param request_id:  The request_id of the request.
    :param src_url:     The src_url of the request.
    :param session:     The database session to use.
    :param logger:      Optional decorated logger that can be passed from the calling daemons or servers.
    """

    try:
        if not request_id:
            return None, None

        sources = get_sources(request_id, session=session)
        sources = sources or []
        for source in sources:
            if source['url'] == src_url:
                src_rse_id = source['rse_id']
                src_rse_name = get_rse_name(src_rse_id, session=session)
                logger(logging.DEBUG, "Find rse name %s for %s" % (src_rse_name, src_url))
                return src_rse_name, src_rse_id
        # cannot find matched surl
        logger(logging.WARNING, 'Cannot get correct RSE for source url: %s' % (src_url))
        return None, None
    except Exception:
        logger(logging.ERROR, 'Cannot get correct RSE for source url: %s' % (src_url), exc_info=True)
        return None, None


@stream_session
def list_requests(src_rse_ids, dst_rse_ids, states=None, session=None):
    """
    List all requests in a specific state from a source RSE to a destination RSE.

    :param src_rse_ids: source RSE ids.
    :param dst_rse_ids: destination RSE ids.
    :param states: list of request states.
    :param session: The database session in use.
    """
    if not states:
        states = [RequestState.WAITING]

    stmt = select(
        models.Request
    ).where(
        models.Request.state.in_(states),
        models.Request.source_rse_id.in_(src_rse_ids),
        models.Request.dest_rse_id.in_(dst_rse_ids)
    )
    for request in session.execute(stmt).yield_per(500).scalars():
        yield request


@stream_session
def list_requests_history(src_rse_ids, dst_rse_ids, states=None, offset=None, limit=None, session=None):
    """
    List all historical requests in a specific state from a source RSE to a destination RSE.

    :param src_rse_ids: source RSE ids.
    :param dst_rse_ids: destination RSE ids.
    :param states: list of request states.
    :param offset: offset (for paging).
    :param limit: limit number of results.
    :param session: The database session in use.
    """
    if not states:
        states = [RequestState.WAITING]

    stmt = select(
        models.RequestHistory
    ).filter(
        models.RequestHistory.state.in_(states),
        models.RequestHistory.source_rse_id.in_(src_rse_ids),
        models.RequestHistory.dest_rse_id.in_(dst_rse_ids)
    )
    if offset:
        stmt = stmt.offset(offset)
    if limit:
        stmt = stmt.limit(limit)
    for request in session.execute(stmt).yield_per(500).scalars():
        yield request
