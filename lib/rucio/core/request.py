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
import itertools
import json
import logging
import math
import random
import threading
import traceback
import uuid
from abc import ABCMeta, abstractmethod
from collections import namedtuple, defaultdict
from collections.abc import Sequence, Mapping, Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional, Union

from sqlalchemy import and_, or_, update, select, delete, exists, insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import aliased
from sqlalchemy.sql.expression import asc, true, false, null, func

from rucio.common.config import config_get_bool, config_get_int
from rucio.common.exception import RequestNotFound, RucioException, UnsupportedOperation, InvalidRSEExpression
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid, chunks
from rucio.core.distance import get_distances
from rucio.core.message import add_message, add_messages
from rucio.core.monitor import MetricManager
from rucio.core.rse import get_rse_attribute, get_rse_name, get_rse_vo, RseData, RseCollection
from rucio.core.rse_expression_parser import parse_expression
from rucio.db.sqla import models, filter_thread_work
from rucio.db.sqla.constants import RequestState, RequestType, LockState, RequestErrMsg, ReplicaState, TransferLimitDirection
from rucio.db.sqla.session import read_session, transactional_session, stream_session
from rucio.db.sqla.util import temp_table_mngr

RequestAndState = namedtuple('RequestAndState', ['request_id', 'request_state'])

if TYPE_CHECKING:

    from sqlalchemy.orm import Session
    from rucio.rse.protocols.protocol import RSEProtocol

"""
The core request.py is specifically for handling requests.
Requests accessed by external_id (So called transfers), are covered in the core transfer.py
"""

METRICS = MetricManager(module=__name__)

TRANSFER_TIME_BUCKETS = (
    10, 30, 60, 5 * 60, 10 * 60, 20 * 60, 40 * 60, 60 * 60, 1.5 * 60 * 60, 3 * 60 * 60, 6 * 60 * 60,
    12 * 60 * 60, 24 * 60 * 60, 3 * 24 * 60 * 60, 4 * 24 * 60 * 60, 5 * 24 * 60 * 60,
    6 * 24 * 60 * 60, 7 * 24 * 60 * 60, 10 * 24 * 60 * 60, 14 * 24 * 60 * 60, 30 * 24 * 60 * 60,
    float('inf')
)


class RequestSource:
    def __init__(self, rse: RseData, ranking=None, distance=None, file_path=None, scheme=None, url=None):
        self.rse = rse
        self.distance = distance if distance is not None else 9999
        self.ranking = ranking if ranking is not None else 0
        self.file_path = file_path
        self.scheme = scheme
        self.url = url

    def __str__(self):
        return "src_rse={}".format(self.rse)


class TransferDestination:
    def __init__(self, rse: RseData, scheme):
        self.rse = rse
        self.scheme = scheme

    def __str__(self):
        return "dst_rse={}".format(self.rse)


class RequestWithSources:
    def __init__(
            self,
            id_: Optional[str],
            request_type: RequestType,
            rule_id: Optional[str],
            scope: InternalScope,
            name: str,
            md5: str,
            adler32: str,
            byte_count: int,
            activity: str,
            attributes: Optional[Union[str, dict[str, Any]]],
            previous_attempt_id: Optional[str],
            dest_rse: RseData,
            account: InternalAccount,
            retry_count: int,
            priority: int,
            transfertool: str,
            requested_at: Optional[datetime.datetime] = None,
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
        self.dest_rse = dest_rse
        self.account = account
        self.retry_count = retry_count or 0
        self.priority = priority if priority is not None else 3
        self.transfertool = transfertool
        self.requested_at = requested_at if requested_at else datetime.datetime.utcnow()

        self.sources: list[RequestSource] = []
        self.requested_source: Optional[RequestSource] = None

    def __str__(self):
        return "{}({}:{})".format(self.request_id, self.scope, self.name)

    @property
    def attributes(self):
        if self._dict_attributes is None:
            self._dict_attributes = self._parse_db_attributes(self._db_attributes)
        return self._dict_attributes

    @attributes.setter
    def attributes(self, db_attributes):
        self._dict_attributes = self._parse_db_attributes(db_attributes)

    @staticmethod
    def _parse_db_attributes(db_attributes):
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
        return attr


class DirectTransfer(metaclass=ABCMeta):
    """
    The configuration for a direct (non-multi-hop) transfer. It can be a multi-source transfer.
    """

    def __init__(self, sources: list[RequestSource], rws: RequestWithSources) -> None:
        self.sources: list[RequestSource] = sources
        self.rws: RequestWithSources = rws

    @property
    @abstractmethod
    def src(self) -> RequestSource:
        pass

    @property
    @abstractmethod
    def dst(self) -> TransferDestination:
        pass

    @property
    @abstractmethod
    def dest_url(self) -> str:
        pass

    @abstractmethod
    def source_url(self, source: RequestSource) -> str:
        pass

    @abstractmethod
    def dest_protocol(self) -> "RSEProtocol":
        pass

    @abstractmethod
    def source_protocol(self, source: RequestSource) -> "RSEProtocol":
        pass


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


@METRICS.time_it
@transactional_session
def requeue_and_archive(request, source_ranking_update=True, retry_protocol_mismatches=False, *, session: "Session", logger=logging.log):
    """
    Requeue and archive a failed request.
    TODO: Multiple requeue.

    :param request:               Original request.
    :param source_ranking_update  Boolean. If True, the source ranking is decreased (making the sources less likely to be used)
    :param session:               Database session to use.
    :param logger:                Optional decorated logger that can be passed from the calling daemons or servers.
    """

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


@METRICS.count_it
@transactional_session
def queue_requests(requests, *, session: "Session", logger=logging.log):
    """
    Submit transfer requests on destination RSEs for data identifiers.

    :param requests:  List of dictionaries containing request metadata.
    :param session:   Database session to use.
    :param logger:    Optional decorated logger that can be passed from the calling daemons or servers.
    :returns:         List of Request-IDs as 32 character hex strings.
    """
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
        session.execute(insert(models.Request), requests_chunk)

    for sources_chunk in chunks(sources, 1000):
        session.execute(insert(models.Source), sources_chunk)

    add_messages(messages, session=session)

    return new_requests


@transactional_session
def list_and_mark_transfer_requests_and_source_replicas(
        rse_collection: "RseCollection",
        processed_by: Optional[str] = None,
        processed_at_delay: int = 600,
        total_workers: int = 0,
        worker_number: int = 0,
        partition_hash_var: Optional[str] = None,
        limit: Optional[int] = None,
        activity: Optional[str] = None,
        older_than: Optional[datetime.datetime] = None,
        rses: Optional[Sequence[str]] = None,
        request_type: Optional[list[RequestType]] = None,
        request_state: Optional[RequestState] = None,
        required_source_rse_attrs: Optional[list[str]] = None,
        ignore_availability: bool = False,
        transfertool: Optional[str] = None,
        *,
        session: "Session",
) -> dict[str, RequestWithSources]:
    """
    List requests with source replicas
    :param rse_collection: the RSE collection being used
    :param processed_by: the daemon/executable running this query
    :param processed_at_delay: how many second to ignore a request if it's already being processed by the same daemon
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

    if processed_by:
        sub_requests = sub_requests.where(
            or_(
                models.Request.last_processed_by.is_(null()),
                models.Request.last_processed_by != processed_by,
                models.Request.last_processed_at < datetime.datetime.utcnow() - datetime.timedelta(seconds=processed_at_delay)
            )
        )

    if not ignore_availability:
        sub_requests = sub_requests.where(models.RSE.availability_write == true())

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

    if rses:
        temp_table_cls = temp_table_mngr(session).create_id_table()

        session.execute(insert(temp_table_cls), [{'id': rse_id} for rse_id in rses])

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
        models.Distance.distance
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
                    1
                ).where(
                    rse_attr_alias.rse_id == models.RSE.id,
                    rse_attr_alias.key == attribute
                )
            )
        )

    requests_by_id = {}
    for (request_id, req_type, rule_id, scope, name, md5, adler32, byte_count, activity, attributes, previous_attempt_id, source_rse_id, dest_rse_id, account, retry_count,
         priority, transfertool, requested_at, replica_rse_id, replica_rse_name, file_path, source_ranking, source_url, distance) in session.execute(stmt):

        request = requests_by_id.get(request_id)
        if not request:
            request = RequestWithSources(id_=request_id, request_type=req_type, rule_id=rule_id, scope=scope, name=name,
                                         md5=md5, adler32=adler32, byte_count=byte_count, activity=activity, attributes=attributes,
                                         previous_attempt_id=previous_attempt_id, dest_rse=rse_collection[dest_rse_id],
                                         account=account, retry_count=retry_count, priority=priority, transfertool=transfertool,
                                         requested_at=requested_at)
            requests_by_id[request_id] = request
            # if STAGEIN and destination RSE is QoS make sure the source is included
            if request.request_type == RequestType.STAGEIN and get_rse_attribute(rse_id=dest_rse_id, key='staging_required', session=session):
                source = RequestSource(rse=rse_collection[dest_rse_id])
                request.sources.append(source)

        if replica_rse_id is not None:
            replica_rse = rse_collection[replica_rse_id]
            replica_rse.name = replica_rse_name
            source = RequestSource(rse=replica_rse, file_path=file_path,
                                   ranking=source_ranking, distance=distance, url=source_url)
            request.sources.append(source)
            if source_rse_id == replica_rse_id:
                request.requested_source = source

    if processed_by:
        for chunk in chunks(requests_by_id, 100):
            stmt = update(
                models.Request
            ).where(
                models.Request.id.in_(chunk)
            ).execution_options(
                synchronize_session=False
            ).values(
                {
                    models.Request.last_processed_by: processed_by,
                    models.Request.last_processed_at: datetime.datetime.now(),
                }
            )
            session.execute(stmt)

    return requests_by_id


@read_session
def fetch_paths(request_id, *, session: "Session"):
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


@METRICS.time_it
@transactional_session
def get_and_mark_next(
        rse_collection: "RseCollection",
        request_type,
        state,
        processed_by: Optional[str] = None,
        processed_at_delay: int = 600,
        limit: int = 100,
        older_than: "Optional[datetime.datetime]" = None,
        rse_id: "Optional[str]" = None,
        activity: "Optional[str]" = None,
        total_workers: int = 0,
        worker_number: int = 0,
        mode_all=False,
        hash_variable='id',
        activity_shares=None,
        include_dependent=True,
        transfertool=None,
        *,
        session: "Session"
):
    """
    Retrieve the next requests matching the request type and state.
    Workers are balanced via hashing to reduce concurrency on database.

    :param rse_collection:    the RSE collection being used
    :param request_type:      Type of the request as a string or list of strings.
    :param state:             State of the request as a string or list of strings.
    :param processed_by:      the daemon/executable running this query
    :param processed_at_delay: how many second to ignore a request if it's already being processed by the same daemon
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
    METRICS.counter('get_next.requests.{request_type}.{state}').labels(request_type=request_type_metric_label, state=state_metric_label).inc()

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
            models.Request.id
        ).where(
            models.Request.state.in_(state),
            models.Request.request_type.in_(request_type)
        ).order_by(
            asc(models.Request.updated_at)
        )
        if processed_by:
            query = query.where(
                or_(
                    models.Request.last_processed_by.is_(null()),
                    models.Request.last_processed_by != processed_by,
                    models.Request.last_processed_at < datetime.datetime.utcnow() - datetime.timedelta(seconds=processed_at_delay)
                )
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

        if session.bind.dialect.name == 'oracle':
            query = select(
                models.Request
            ).where(
                models.Request.id.in_(query)
            ).with_for_update(
                skip_locked=True
            )
        else:
            query = query.with_only_columns(
                models.Request
            ).with_for_update(
                skip_locked=True,
                of=models.Request.last_processed_by
            )
        query_result = session.execute(query).scalars()
        if query_result:
            if mode_all:
                for res in query_result:
                    res_dict = res.to_dict()
                    res_dict['request_id'] = res_dict['id']
                    res_dict['attributes'] = json.loads(str(res_dict['attributes'] or '{}'))

                    dst_id = res_dict['dest_rse_id']
                    src_id = res_dict['source_rse_id']
                    res_dict['dst_rse'] = rse_collection[dst_id].ensure_loaded(load_name=True, load_attributes=True)
                    res_dict['src_rse'] = rse_collection[src_id].ensure_loaded(load_name=True, load_attributes=True) if src_id is not None else None

                    result.append(res_dict)
            else:
                for res in query_result:
                    result.append({'request_id': res.id, 'external_host': res.external_host, 'external_id': res.external_id})

            request_ids = {r['request_id'] for r in result}
            if processed_by and request_ids:
                for chunk in chunks(request_ids, 100):
                    stmt = update(
                        models.Request
                    ).where(
                        models.Request.id.in_(chunk)
                    ).execution_options(
                        synchronize_session=False
                    ).values(
                        {
                            models.Request.last_processed_by: processed_by,
                            models.Request.last_processed_at: datetime.datetime.now(),
                        }
                    )
                    session.execute(stmt)

    return result


@transactional_session
def update_request(
        request_id: str,
        state: Optional[RequestState] = None,
        transferred_at: Optional[datetime.datetime] = None,
        started_at: Optional[datetime.datetime] = None,
        staging_started_at: Optional[datetime.datetime] = None,
        staging_finished_at: Optional[datetime.datetime] = None,
        source_rse_id: Optional[str] = None,
        err_msg: Optional[str] = None,
        attributes: Optional[dict[str, str]] = None,
        priority: Optional[int] = None,
        transfertool: Optional[str] = None,
        *,
        raise_on_missing: bool = False,
        session: "Session",
):

    rowcount = 0
    try:
        update_items: dict[Any, Any] = {
            models.Request.updated_at: datetime.datetime.utcnow()
        }
        if state is not None:
            update_items[models.Request.state] = state
        if transferred_at is not None:
            update_items[models.Request.transferred_at] = transferred_at
        if started_at is not None:
            update_items[models.Request.started_at] = started_at
        if staging_started_at is not None:
            update_items[models.Request.staging_started_at] = staging_started_at
        if staging_finished_at is not None:
            update_items[models.Request.staging_finished_at] = staging_finished_at
        if source_rse_id is not None:
            update_items[models.Request.source_rse_id] = source_rse_id
        if err_msg is not None:
            update_items[models.Request.err_msg] = err_msg
        if attributes is not None:
            update_items[models.Request.attributes] = json.dumps(attributes)
        if priority is not None:
            update_items[models.Request.priority] = priority
        if transfertool is not None:
            update_items[models.Request.transfertool] = transfertool

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

    if not rowcount and raise_on_missing:
        raise UnsupportedOperation("Request %s state cannot be updated." % request_id)

    if rowcount:
        return True
    return False


@METRICS.count_it
@transactional_session
def transition_request_state(
        request_id: str,
        state: Optional[RequestState] = None,
        external_id: Optional[str] = None,
        transferred_at: Optional[datetime.datetime] = None,
        started_at: Optional[datetime.datetime] = None,
        staging_started_at: Optional[datetime.datetime] = None,
        staging_finished_at: Optional[datetime.datetime] = None,
        source_rse_id: Optional[str] = None,
        err_msg: Optional[str] = None,
        attributes: Optional[dict[str, str]] = None,
        *,
        request: "Optional[dict[str, Any]]" = None,
        session: "Session",
        logger=logging.log
) -> bool:
    """
    Update the request if its state changed. Return a boolean showing if the request was actually updated or not.
    """

    # TODO: Should this be a private method?

    if request is None:
        request = get_request(request_id, session=session)

    if not request:
        # The request was deleted in the meantime. Ignore it.
        logger(logging.WARNING, "Request %s not found. Cannot set its state to %s", request_id, state)
        return False

    if request['state'] == state:
        logger(logging.INFO, "Request %s state is already %s. Will skip the update.", request_id, state)
        return False

    if state in [RequestState.FAILED, RequestState.DONE, RequestState.LOST] and (request["external_id"] != external_id):
        logger(logging.ERROR, "Request %s should not be updated to 'Failed' or 'Done' without external transfer_id" % request_id)
        return False

    update_request(
        request_id=request_id,
        state=state,
        transferred_at=transferred_at,
        started_at=started_at,
        staging_started_at=staging_started_at,
        staging_finished_at=staging_finished_at,
        source_rse_id=source_rse_id,
        err_msg=err_msg,
        attributes=attributes,
        raise_on_missing=True,
        session=session,
    )
    return True


@METRICS.count_it
@transactional_session
def transition_requests_state_if_possible(request_ids, new_state, *, session: "Session", logger=logging.log):
    """
    Bulk update the state of requests. Skips silently if the request_id does not exist.

    :param request_ids:  List of (Request-ID as a 32 character hex string).
    :param new_state:    New state as string.
    :param session:      Database session to use.
    :param logger:       Optional decorated logger that can be passed from the calling daemons or servers.
    """

    try:
        for request_id in request_ids:
            try:
                transition_request_state(request_id, new_state, session=session, logger=logger)
            except UnsupportedOperation:
                continue
    except IntegrityError as error:
        raise RucioException(error.args)


@METRICS.count_it
@transactional_session
def touch_requests_by_rule(rule_id, *, session: "Session"):
    """
    Update the update time of requests in a rule. Fails silently if no requests on this rule.

    :param rule_id:  Rule-ID as a 32 character hex string.
    :param session:  Database session to use.
    """

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
def get_request(request_id, *, session: "Session"):
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
            tmp = tmp.to_dict()
            tmp['attributes'] = json.loads(str(tmp['attributes'] or '{}'))
            return tmp
    except IntegrityError as error:
        raise RucioException(error.args)


@METRICS.count_it
@read_session
def get_request_by_did(scope, name, rse_id, request_type=None, *, session: "Session"):
    """
    Retrieve a request by its DID for a destination RSE.

    :param scope:          The scope of the data identifier.
    :param name:           The name of the data identifier.
    :param rse_id:         The destination RSE ID of the request.
    :param request_type:   The type of request as rucio.db.sqla.constants.RequestType.
    :param session:        Database session to use.
    :returns:              Request as a dictionary.
    """

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
            tmp = tmp.to_dict()

            tmp['source_rse'] = get_rse_name(rse_id=tmp['source_rse_id'], session=session) if tmp['source_rse_id'] is not None else None
            tmp['dest_rse'] = get_rse_name(rse_id=tmp['dest_rse_id'], session=session) if tmp['dest_rse_id'] is not None else None
            tmp['attributes'] = json.loads(str(tmp['attributes'] or '{}'))

            return tmp
    except IntegrityError as error:
        raise RucioException(error.args)


@METRICS.count_it
@read_session
def get_request_history_by_did(scope, name, rse_id, request_type=None, *, session: "Session"):
    """
    Retrieve a historical request by its DID for a destination RSE.

    :param scope:          The scope of the data identifier.
    :param name:           The name of the data identifier.
    :param rse_id:         The destination RSE ID of the request.
    :param request_type:   The type of request as rucio.db.sqla.constants.RequestType.
    :param session:        Database session to use.
    :returns:              Request as a dictionary.
    """

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
            tmp = tmp.to_dict()

            tmp['source_rse'] = get_rse_name(rse_id=tmp['source_rse_id'], session=session) if tmp['source_rse_id'] is not None else None
            tmp['dest_rse'] = get_rse_name(rse_id=tmp['dest_rse_id'], session=session) if tmp['dest_rse_id'] is not None else None

            return tmp
    except IntegrityError as error:
        raise RucioException(error.args)


def is_intermediate_hop(request):
    """
    Check if the request is an intermediate hop in a multi-hop transfer.
    """
    if (request['attributes'] or {}).get('is_intermediate_hop'):
        return True
    return False


@transactional_session
def handle_failed_intermediate_hop(request, *, session: "Session") -> int:
    """
    Perform housekeeping behind a failed intermediate hop
    Returns the number of updated requests
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
    return len(dependent_requests)


@METRICS.count_it
@transactional_session
def archive_request(request_id, *, session: "Session"):
    """
    Move a request to the history table.

    :param request_id:  Request-ID as a 32 character hex string.
    :param session:     Database session to use.
    """

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
            METRICS.timer('archive_request_per_activity.{activity}').labels(activity=req['activity'].replace(' ', '_')).observe(time_diff_s)
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


@METRICS.count_it
@transactional_session
def cancel_request_did(scope, name, dest_rse_id, request_type=RequestType.TRANSFER, *, session: "Session", logger=logging.log):
    """
    Cancel a request based on a DID and request type.

    :param scope:         Data identifier scope as a string.
    :param name:          Data identifier name as a string.
    :param dest_rse_id:   RSE id as a string.
    :param request_type:  Type of the request.
    :param session:       Database session to use.
    :param logger:        Optional decorated logger that can be passed from the calling daemons or servers.
    """

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
def get_sources(request_id, rse_id=None, *, session: "Session"):
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
                t2 = t.to_dict()
                result.append(t2)

            return result
    except IntegrityError as error:
        raise RucioException(error.args)


@read_session
def get_heavy_load_rses(threshold, *, session: "Session"):
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


class TransferStatsManager:

    @dataclass
    class _StatsRecord:
        files_failed: int = 0
        files_done: int = 0
        bytes_done: int = 0

    def __init__(self):
        self.lock = threading.Lock()

        retentions = sorted([
            # resolution, retention
            (datetime.timedelta(minutes=5), datetime.timedelta(hours=1)),
            (datetime.timedelta(hours=1), datetime.timedelta(days=1)),
            (datetime.timedelta(days=1), datetime.timedelta(days=30)),
        ])

        self.retentions = retentions
        self.raw_resolution, raw_retention = self.retentions[0]

        self.current_timestamp = datetime.datetime(year=1970, month=1, day=1)
        self.current_samples = defaultdict()
        self._rollover_samples(rollover_time=datetime.datetime.utcnow())

        self.record_stats = True
        self.save_timer = None
        self.downsample_timer = None
        self.downsample_period = math.ceil(raw_retention.total_seconds())

    def __enter__(self):
        self.record_stats = config_get_bool('transfers', 'stats_enabled', default=self.record_stats)
        downsample_period = config_get_int('transfers', 'stats_downsample_period', default=self.downsample_period)
        # Introduce some voluntary jitter to reduce the likely-hood of performing this database
        # operation multiple times in parallel.
        self.downsample_period = random.randint(downsample_period * 3 // 4, math.ceil(downsample_period * 5 / 4))
        if self.record_stats:
            self.save_timer = threading.Timer(self.raw_resolution.total_seconds(), self.periodic_save)
            self.save_timer.start()
            self.downsample_timer = threading.Timer(self.downsample_period, self.periodic_downsample_and_cleanup)
            self.downsample_timer.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.save_timer is not None:
            self.save_timer.cancel()
        if self.downsample_timer is not None:
            self.downsample_timer.cancel()
        if self.record_stats:
            self.force_save()

    def observe(
            self,
            src_rse_id: str,
            dst_rse_id: str,
            activity: str,
            state: RequestState,
            file_size: int,
            *,
            submitted_at: Optional[datetime.datetime] = None,
            started_at: Optional[datetime.datetime] = None,
            transferred_at: Optional[datetime.datetime] = None,
            session: "Optional[Session]" = None
    ) -> None:
        """
        Increment counters for the given (source_rse, destination_rse, activity) as a result of
        successful or failed transfer.
        """
        if not self.record_stats:
            return
        now = datetime.datetime.utcnow()
        with self.lock:
            save_timestamp, save_samples = now, {}
            if now >= self.current_timestamp + self.raw_resolution:
                save_timestamp, save_samples = self._rollover_samples(now)

            if state in (RequestState.DONE, RequestState.FAILED):
                record = self.current_samples[dst_rse_id, src_rse_id, activity]
                if state == RequestState.DONE:
                    record.files_done += 1
                    record.bytes_done += file_size

                    if submitted_at is not None and started_at is not None:
                        wait_time = (started_at - submitted_at).total_seconds()
                        METRICS.timer(name='wait_time', buckets=TRANSFER_TIME_BUCKETS).observe(wait_time)
                        if transferred_at is not None:
                            transfer_time = (transferred_at - started_at).total_seconds()
                            METRICS.timer(name='transfer_time', buckets=TRANSFER_TIME_BUCKETS).observe(transfer_time)
                else:
                    record.files_failed += 1
        if save_samples:
            self._save_samples(timestamp=save_timestamp, samples=save_samples, session=session)

    def periodic_save(self):
        """
        Save samples to the database if the end of the current recording interval was reached.
        Opportunistically perform down-sampling.
        """
        self.save_timer = threading.Timer(self.raw_resolution.total_seconds(), self.periodic_save)
        self.save_timer.start()

        now = datetime.datetime.utcnow()
        with self.lock:
            save_timestamp, save_samples = now, {}
            if now >= self.current_timestamp + self.raw_resolution:
                save_timestamp, save_samples = self._rollover_samples(now)
        if save_samples:
            self._save_samples(timestamp=save_timestamp, samples=save_samples)

    @transactional_session
    def force_save(self, *, session: "Session") -> None:
        """
        Commit to the database everything without ensuring that
        the end of the currently recorded time interval is reached.

        Only to be used for the final save operation on shutdown.
        """
        with self.lock:
            save_timestamp, save_samples = self._rollover_samples(datetime.datetime.utcnow())
        if save_samples:
            self._save_samples(timestamp=save_timestamp, samples=save_samples, session=session)

    def _rollover_samples(self, rollover_time: datetime.datetime) -> "tuple[datetime.datetime, Mapping[tuple[str, str, str], TransferStatsManager._StatsRecord]]":
        previous_samples = (self.current_timestamp, self.current_samples)
        self.current_samples = defaultdict(lambda: self._StatsRecord())
        _, self.current_timestamp = next(self.slice_time(self.raw_resolution, start_time=rollover_time + self.raw_resolution))
        return previous_samples

    @transactional_session
    def _save_samples(
            self,
            timestamp: "datetime.datetime",
            samples: "Mapping[tuple[str, str, str], TransferStatsManager._StatsRecord]",
            *,
            session: "Session"
    ) -> None:
        """
        Commit the provided samples to the database.
        """
        rows_to_insert = []
        for (dst_rse_id, src_rse_id, activity), record in samples.items():
            rows_to_insert.append({
                models.TransferStats.timestamp.name: timestamp,
                models.TransferStats.resolution.name: self.raw_resolution.total_seconds(),
                models.TransferStats.src_rse_id.name: src_rse_id,
                models.TransferStats.dest_rse_id.name: dst_rse_id,
                models.TransferStats.activity.name: activity,
                models.TransferStats.files_failed.name: record.files_failed,
                models.TransferStats.files_done.name: record.files_done,
                models.TransferStats.bytes_done.name: record.bytes_done,
            })
        if rows_to_insert:
            session.execute(insert(models.TransferStats), rows_to_insert)

    def periodic_downsample_and_cleanup(self):
        """
        Periodically create lower resolution samples from higher resolution ones.
        """
        self.downsample_timer = threading.Timer(self.downsample_period, self.periodic_downsample_and_cleanup)
        self.downsample_timer.start()

        while self.downsample_and_cleanup():
            continue

    @read_session
    def _db_time_ranges(self, *, session: "Session") -> "dict[datetime.timedelta, tuple[datetime.datetime, datetime.datetime]]":

        stmt = select(
            models.TransferStats.resolution,
            func.max(models.TransferStats.timestamp),
            func.min(models.TransferStats.timestamp),
        ).group_by(
            models.TransferStats.resolution,
        )
        db_time_ranges = {
            datetime.timedelta(seconds=res): (newest_t, oldest_t)
            for res, newest_t, oldest_t in session.execute(stmt)
        }
        return db_time_ranges

    @transactional_session
    def downsample_and_cleanup(self, *, session: "Session") -> bool:
        """
        Housekeeping of samples in the database:
            - create lower-resolution (but higher-retention) samples from higher-resolution ones;
            - delete the samples which are older than the desired retention time.
        Return True if it thinks there is still more cleanup.

        This function handles safely to be executed in parallel from multiple daemons at the
        same time. However, this is achieved at the cost of introducing duplicate samples at lower
        resolution into the database. The possibility of having duplicates at lower resolutions must be
        considered during work with those sample. Code must tolerate duplicates and avoid double-counting.
        """

        # Delay processing to leave time for all raw metrics to be correctly saved to the database
        now = datetime.datetime.utcnow() - 4 * self.raw_resolution

        db_time_ranges = self._db_time_ranges(session=session)

        more_to_delete = False
        id_temp_table = temp_table_mngr(session).create_id_table()
        for i in range(1, len(self.retentions)):
            src_resolution, desired_src_retention = self.retentions[i - 1]
            dst_resolution, desired_dst_retention = self.retentions[i]

            # Always keep samples at source resolution aligned to the destination resolution interval.
            # Keep, at least, the amount of samples needed to cover the first interval at
            # destination resolution, but keep more samples if explicitly configured to do so.
            oldest_desired_src_timestamp, _ = next(self.slice_time(dst_resolution, start_time=now - desired_src_retention))

            _, oldest_available_src_timestamp = db_time_ranges.get(src_resolution, (None, None))
            newest_available_dst_timestamp, oldest_available_dst_timestamp = db_time_ranges.get(dst_resolution, (None, None))
            # Only generate down-samples at destination resolution for interval in which:
            # - are within the desired retention window
            oldest_time_to_handle = now - desired_dst_retention - dst_resolution
            # - we didn't already generate the corresponding sample at destination resolution
            if newest_available_dst_timestamp:
                oldest_time_to_handle = max(oldest_time_to_handle, newest_available_dst_timestamp + datetime.timedelta(seconds=1))
            # - we have samples at source resolution to do it
            if oldest_available_src_timestamp:
                oldest_time_to_handle = max(oldest_time_to_handle, oldest_available_src_timestamp)
            else:
                oldest_time_to_handle = now

            # Create samples at lower resolution from samples at higher resolution
            for recent_t, older_t in self.slice_time(dst_resolution, start_time=now, end_time=oldest_time_to_handle):
                additional_fields = {
                    models.TransferStats.timestamp.name: older_t,
                    models.TransferStats.resolution.name: dst_resolution.total_seconds(),
                }
                src_totals = self._load_totals(resolution=src_resolution, recent_t=recent_t, older_t=older_t, session=session)
                downsample_stats = [stat | additional_fields for stat in src_totals]
                if downsample_stats:
                    session.execute(insert(models.TransferStats), downsample_stats)
                    if not oldest_available_dst_timestamp or older_t < oldest_available_dst_timestamp:
                        oldest_available_dst_timestamp = older_t
                    if not newest_available_dst_timestamp or older_t > newest_available_dst_timestamp:
                        newest_available_dst_timestamp = older_t

            if oldest_available_dst_timestamp and newest_available_dst_timestamp:
                db_time_ranges[dst_resolution] = (newest_available_dst_timestamp, oldest_available_dst_timestamp)

            # Delete from the database the samples which are older than desired
            more_to_delete |= self._cleanup(
                id_temp_table=id_temp_table,
                resolution=src_resolution,
                timestamp=oldest_desired_src_timestamp,
                session=session
            )

        # Cleanup samples at the lowest resolution, which were not handled by the previous loop
        last_resolution, last_retention = self.retentions[-1]
        _, oldest_desired_timestamp = next(self.slice_time(last_resolution, start_time=now - last_retention))
        if db_time_ranges.get(last_resolution, (now, now))[1] < oldest_desired_timestamp:
            more_to_delete |= self._cleanup(
                id_temp_table=id_temp_table,
                resolution=last_resolution,
                timestamp=oldest_desired_timestamp,
                session=session
            )

        # Cleanup all resolutions which exist in the database but are not desired by rucio anymore
        # (probably due to configuration changes).
        for resolution_to_cleanup in set(db_time_ranges).difference(r[0] for r in self.retentions):
            more_to_delete |= self._cleanup(
                id_temp_table=id_temp_table,
                resolution=resolution_to_cleanup,
                timestamp=now,
                session=session
            )
        return more_to_delete

    @stream_session
    def load_totals(
            self,
            older_t: "datetime.datetime",
            dest_rse_id: "Optional[str]" = None,
            src_rse_id: "Optional[str]" = None,
            activity: "Optional[str]" = None,
            by_activity: bool = True,
            *,
            session: "Session"
    ) -> "Iterator[Mapping[str, str | int]]":
        """
        Load totals from now up to older_t in the past by automatically picking the best resolution.

        The results will not necessarily be uniquely grouped by src_rse/dest_rse/activity. The caller
        is responsible for summing identical src_rse/dest_rse/activity pairs to get the actual result
        """

        db_time_ranges = self._db_time_ranges(session=session)

        oldest_fetched = older_t
        for resolution, retention in reversed(self.retentions):
            newest_available_db_timestamp, oldest_available_db_timestamp = db_time_ranges.get(resolution, (None, None))

            if not (newest_available_db_timestamp and oldest_available_db_timestamp):
                continue

            if newest_available_db_timestamp < oldest_fetched:
                continue

            yield from self._load_totals(
                resolution=resolution,
                recent_t=newest_available_db_timestamp + datetime.timedelta(seconds=1),
                older_t=oldest_fetched + datetime.timedelta(seconds=1),
                dest_rse_id=dest_rse_id,
                src_rse_id=src_rse_id,
                activity=activity,
                by_activity=by_activity,
                session=session,
            )
            oldest_fetched = newest_available_db_timestamp + resolution

    @stream_session
    def _load_totals(
            self,
            resolution: "datetime.timedelta",
            recent_t: "datetime.datetime",
            older_t: "datetime.datetime",
            dest_rse_id: "Optional[str]" = None,
            src_rse_id: "Optional[str]" = None,
            activity: "Optional[str]" = None,
            by_activity: bool = True,
            *,
            session: "Session"
    ) -> "Iterator[Mapping[str, str | int]]":
        """
        Load aggregated totals for the given resolution and time interval.

        Ignore multiple values for the same timestamp at downsample resolutions.
        They are result of concurrent downsample operations (two different
        daemons performing downsampling at the same time). Very probably,
        the values are identical. Eve if not, these values must not be counted twice.
        This is to gracefully handle multiple parallel downsample operations.
        """
        grouping: "list[Any]" = [
            models.TransferStats.src_rse_id,
            models.TransferStats.dest_rse_id,
        ]
        if by_activity:
            grouping.append(models.TransferStats.activity)

        if resolution == self.raw_resolution:
            sub_query = select(
                models.TransferStats.timestamp,
                *grouping,
                models.TransferStats.files_failed,
                models.TransferStats.files_done,
                models.TransferStats.bytes_done
            )
        else:
            sub_query = select(
                models.TransferStats.timestamp,
                *grouping,
                func.max(models.TransferStats.files_failed).label(models.TransferStats.files_failed.name),
                func.max(models.TransferStats.files_done).label(models.TransferStats.files_done.name),
                func.max(models.TransferStats.bytes_done).label(models.TransferStats.bytes_done.name),
            ).group_by(
                models.TransferStats.timestamp,
                *grouping,
            )

        sub_query = sub_query.where(
            models.TransferStats.resolution == resolution.total_seconds(),
            models.TransferStats.timestamp >= older_t,
            models.TransferStats.timestamp < recent_t
        )
        if dest_rse_id:
            sub_query = sub_query.where(
                models.TransferStats.dest_rse_id == dest_rse_id
            )
        if src_rse_id:
            sub_query = sub_query.where(
                models.TransferStats.src_rse_id == src_rse_id
            )
        if activity:
            sub_query = sub_query.where(
                models.TransferStats.activity == activity
            )

        sub_query = sub_query.subquery()

        grouping = [
            sub_query.c.src_rse_id,
            sub_query.c.dest_rse_id,
        ]
        if by_activity:
            grouping.append(sub_query.c.activity)

        stmt = select(
            *grouping,
            func.sum(sub_query.c.files_failed).label(models.TransferStats.files_failed.name),
            func.sum(sub_query.c.files_done).label(models.TransferStats.files_done.name),
            func.sum(sub_query.c.bytes_done).label(models.TransferStats.bytes_done.name),
        ).group_by(
            *grouping,
        )

        for row in session.execute(stmt):
            yield row._asdict()

    @staticmethod
    def _cleanup(
            id_temp_table,
            resolution: "datetime.timedelta",
            timestamp: "datetime.datetime",
            limit: "Optional[int]" = 10000,
            *,
            session: "Session"
    ) -> bool:
        """
        Delete, from the database, the stats older than the given time.
        Skip locked rows, to tolerate parallel executions by multiple daemons.
        """
        stmt = select(
            models.TransferStats.id
        ).where(
            models.TransferStats.resolution == resolution.total_seconds(),
            models.TransferStats.timestamp < timestamp
        )

        if limit is not None:
            stmt = stmt.limit(limit)

        # Oracle does not support chaining order_by(), limit(), and
        # with_for_update(). Use a nested query to overcome this.
        if session.bind.dialect.name == 'oracle':
            stmt = select(
                models.TransferStats.id
            ).where(
                models.TransferStats.id.in_(stmt)
            ).with_for_update(
                skip_locked=True
            )
        else:
            stmt = stmt.with_for_update(skip_locked=True)

        session.execute(delete(id_temp_table))
        session.execute(insert(id_temp_table).from_select(['id'], stmt))

        stmt = delete(
            models.TransferStats
        ).where(
            exists(select(1).where(models.TransferStats.id == id_temp_table.id))
        ).execution_options(
            synchronize_session=False
        )
        res = session.execute(stmt)
        return res.rowcount > 0

    @staticmethod
    def slice_time(
            resolution: datetime.timedelta,
            start_time: "Optional[datetime.datetime]" = None,
            end_time: "Optional[datetime.datetime]" = None
    ) -> Iterator[tuple[datetime.datetime, datetime.datetime]]:
        """
        Iterates, back in time, over time intervals of length `resolution` which are fully
        included within the input interval (start_time, end_time).
        Intervals are aligned on boundaries divisible by resolution.

        For example: for start_time=17:09:59, end_time=16:20:01 and resolution = 10minutes, it will yield
        (17:00:00, 16:50:00), (16:50:00, 16:40:00), (16:40:00, 16:30:00)
        """

        if start_time is None:
            start_time = datetime.datetime.utcnow()
        newer_t = datetime.datetime.fromtimestamp(int(start_time.timestamp()) // resolution.total_seconds() * resolution.total_seconds())
        older_t = newer_t - resolution
        while not end_time or older_t >= end_time:
            yield newer_t, older_t
            newer_t = older_t
            older_t = older_t - resolution


@read_session
def get_request_metrics(
        dest_rse_id: "Optional[str]" = None,
        src_rse_id: "Optional[str]" = None,
        activity: "Optional[str]" = None,
        *,
        session: "Session"
):
    metrics = {}
    now = datetime.datetime.utcnow()

    # Add the current queues
    db_stats = get_request_stats(
        state=[
            RequestState.QUEUED,
        ],
        src_rse_id=src_rse_id,
        dest_rse_id=dest_rse_id,
        activity=activity,
        session=session,
    )
    for stat in db_stats:
        if not stat.source_rse_id:
            continue

        resp_elem = metrics.setdefault((stat.source_rse_id, stat.dest_rse_id), {})

        files_elem = resp_elem.setdefault('files', {})
        files_elem.setdefault('queued', {})[stat.activity] = stat.counter
        files_elem['queued-total'] = files_elem.get('queued-total', 0) + stat.counter

        bytes_elem = resp_elem.setdefault('bytes', {})
        bytes_elem.setdefault('queued', {})[stat.activity] = stat.bytes
        bytes_elem['queued-total'] = bytes_elem.get('queued-total', 0) + stat.bytes

    # Add the historical data
    for duration, duration_label in (
            (datetime.timedelta(hours=1), '1h'),
            (datetime.timedelta(hours=6), '6h')
    ):
        db_stats = TransferStatsManager().load_totals(
            older_t=now - duration,
            dest_rse_id=dest_rse_id,
            src_rse_id=src_rse_id,
            activity=activity,
            session=session,
        )

        for stat in db_stats:
            resp_elem = metrics.setdefault((stat['src_rse_id'], stat['dest_rse_id']), {})

            files_elem = resp_elem.setdefault('files', {})
            if stat['files_done']:
                activity_elem = files_elem.setdefault('done', {}).setdefault(stat['activity'], {})
                activity_elem[duration_label] = activity_elem.get(duration_label, 0) + stat['files_done']
                files_elem[f'done-total-{duration_label}'] = files_elem.get(f'done-total-{duration_label}', 0) + stat['files_done']
            if stat['files_failed']:
                activity_elem = files_elem.setdefault('failed', {}).setdefault(stat['activity'], {})
                activity_elem[duration_label] = activity_elem.get(duration_label, 0) + stat['files_failed']
                files_elem[f'failed-total-{duration_label}'] = files_elem.get(f'failed-total-{duration_label}', 0) + stat['files_failed']

            bytes_elem = resp_elem.setdefault('bytes', {})
            if stat['bytes_done']:
                activity_elem = bytes_elem.setdefault('done', {}).setdefault(stat['activity'], {})
                activity_elem[duration_label] = activity_elem.get(duration_label, 0) + stat['bytes_done']
            bytes_elem[f'done-total-{duration_label}'] = bytes_elem.get(f'done-total-{duration_label}', 0) + stat['bytes_done']

    # Add distances
    for distance in get_distances(dest_rse_id=dest_rse_id, src_rse_id=src_rse_id):
        resp_elem = metrics.setdefault((distance['src_rse_id'], distance['dest_rse_id']), {})

        resp_elem['distance'] = distance['distance']

    # Fill RSE names
    rses = RseCollection(rse_ids=itertools.chain.from_iterable(metrics))
    rses.ensure_loaded(load_name=True, include_deleted=True)
    response = {}
    for (src_id, dst_id), metric in metrics.items():
        src_rse = rses[src_id]
        dst_rse = rses[dst_id]
        metric['src_rse'] = src_rse.name
        metric['dst_rse'] = dst_rse.name

        response[f'{src_rse.name}:{dst_rse.name}'] = metric

    return response


@read_session
def get_request_stats(
        state: "RequestState | list[RequestState]",
        dest_rse_id: "Optional[str]" = None,
        src_rse_id: "Optional[str]" = None,
        activity: "Optional[str]" = None,
        *,
        session: "Session"
):
    """
    Retrieve statistics about requests by destination, activity and state.
    """

    if not isinstance(state, list):
        state = [state]

    try:
        stmt = select(
            models.Request.account,
            models.Request.state,
            models.Request.dest_rse_id,
            models.Request.source_rse_id,
            models.Request.activity,
            func.count(1).label('counter'),
            func.sum(models.Request.bytes).label('bytes')
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
        if src_rse_id:
            stmt = stmt.where(
                models.Request.source_rse_id == src_rse_id
            )
        if dest_rse_id:
            stmt = stmt.where(
                models.Request.dest_rse_id == dest_rse_id
            )
        if activity:
            stmt = stmt.where(
                models.Request.activity == activity
            )

        return session.execute(stmt).all()

    except IntegrityError as error:
        raise RucioException(error.args)


@transactional_session
def release_waiting_requests_per_deadline(
        dest_rse_id: Optional[str] = None,
        source_rse_id: Optional[str] = None,
        deadline: int = 1,
        *,
        session: "Session",
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
            grouped_requests_subquery.c.oldest_requested_at < datetime.datetime.utcnow() - datetime.timedelta(hours=deadline)
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
        dest_rse_id: Optional[str] = None,
        source_rse_id: Optional[str] = None,
        volume: int = 0,
        *,
        session: "Session"
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
        dest_rse_id: Optional[str] = None,
        source_rse_id: Optional[str] = None,
        *,
        session: "Session"
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
        dest_rse_id: Optional[str] = None,
        source_rse_id: Optional[str] = None,
        activity: Optional[str] = None,
        count: int = 0,
        account: Optional[InternalAccount] = None,
        *,
        session: "Session"
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
        dest_rse_id: Optional[str] = None,
        source_rse_id: Optional[str] = None,
        count: int = 0,
        deadline: int = 1,
        volume: int = 0,
        *,
        session: "Session"
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
        dest_rse_id: Optional[str] = None,
        source_rse_id: Optional[str] = None,
        activity: Optional[str] = None,
        account: Optional[InternalAccount] = None,
        *,
        session: "Session"
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


@stream_session
def list_transfer_limits(
        *,
        session: "Session",
):
    stmt = select(
        models.TransferLimit
    )
    for limit in session.execute(stmt).scalars():
        dict_resp = limit.to_dict()
        yield dict_resp


def _sync_rse_transfer_limit(
        limit_id: Union[str, uuid.UUID],
        desired_rse_ids: set[str],
        *,
        session: "Session",
):
    """
    Ensure that an RSETransferLimit exists in the database for each of the given rses (and only for these rses)
    """

    stmt = select(
        models.RSETransferLimit.rse_id,
    ).where(
        models.RSETransferLimit.limit_id == limit_id
    )
    existing_rse_ids = set(session.execute(stmt).scalars())

    rse_limits_to_add = desired_rse_ids.difference(existing_rse_ids)
    rse_limits_to_delete = existing_rse_ids.difference(desired_rse_ids)

    if rse_limits_to_add:
        session.execute(
            insert(models.RSETransferLimit),
            [
                {'rse_id': rse_id, 'limit_id': limit_id}
                for rse_id in rse_limits_to_add
            ]
        )

    if rse_limits_to_delete:
        stmt = delete(
            models.RSETransferLimit
        ).where(
            models.RSETransferLimit.limit_id == limit_id,
            models.RSETransferLimit.rse_id.in_(rse_limits_to_delete)
        )
        session.execute(stmt)


@transactional_session
def re_sync_all_transfer_limits(
        delete_empty: bool = False,
        *,
        session: "Session",
):
    """
    For each TransferLimit in the database, re-evaluate the rse expression and ensure that the
    correct RSETransferLimits are in the database
    :param delete_empty: if True, when rse_expression evaluates to an empty set or is invalid, the limit is completely removed
    """
    stmt = select(
        models.TransferLimit,
    )
    for limit in session.execute(stmt).scalars():
        try:
            desired_rse_ids = {rse['id'] for rse in parse_expression(expression=limit.rse_expression, session=session)}
        except InvalidRSEExpression:
            desired_rse_ids = set()

        if not desired_rse_ids and delete_empty:
            delete_transfer_limit_by_id(limit_id=limit.id, session=session)
        else:
            _sync_rse_transfer_limit(limit_id=limit.id, desired_rse_ids=desired_rse_ids, session=session)


@transactional_session
def set_transfer_limit(
        rse_expression: str,
        activity: Optional[str] = None,
        direction: TransferLimitDirection = TransferLimitDirection.DESTINATION,
        max_transfers: Optional[int] = None,
        volume: Optional[int] = None,
        deadline: Optional[int] = None,
        strategy: Optional[str] = None,
        transfers: Optional[int] = None,
        waitings: Optional[int] = None,
        *,
        session: "Session",
):
    """
    Create or update a transfer limit

    :param rse_expression: RSE expression string.
    :param activity: The activity.
    :param direction: The direction in which this limit applies (source/destination)
    :param max_transfers: Maximum transfers.
    :param volume: Maximum transfer volume in bytes.
    :param deadline: Maximum waiting time in hours until a datasets gets released.
    :param strategy: defines how to handle datasets: `fifo` (each file released separately) or `grouped_fifo` (wait for the entire dataset to fit)
    :param transfers: Current number of active transfers
    :param waitings: Current number of waiting transfers
    :param session: The database session in use.

    :return: the limit id
    """
    if activity is None:
        activity = 'all_activities'

    stmt = select(
        models.TransferLimit
    ).where(
        models.TransferLimit.rse_expression == rse_expression,
        models.TransferLimit.activity == activity,
        models.TransferLimit.direction == direction
    )
    limit = session.execute(stmt).scalar_one_or_none()

    if not limit:
        if max_transfers is None:
            max_transfers = 0
        if volume is None:
            volume = 0
        if deadline is None:
            deadline = 1
        if strategy is None:
            strategy = 'fifo'
        limit = models.TransferLimit(
            rse_expression=rse_expression,
            activity=activity,
            direction=direction,
            max_transfers=max_transfers,
            volume=volume,
            deadline=deadline,
            strategy=strategy,
            transfers=transfers,
            waitings=waitings
        )
        limit.save(session=session)
    else:
        changed = False
        if max_transfers is not None and limit.max_transfers != max_transfers:
            limit.max_transfers = max_transfers
            changed = True
        if volume is not None and limit.volume != volume:
            limit.volume = volume
            changed = True
        if deadline is not None and limit.deadline != deadline:
            limit.deadline = deadline
            changed = True
        if strategy is not None and limit.strategy != strategy:
            limit.strategy = strategy
            changed = True
        if transfers is not None and limit.transfers != transfers:
            limit.transfers = transfers
            changed = True
        if waitings is not None and limit.waitings != waitings:
            limit.waitings = waitings
            changed = True
        if changed:
            limit.save(session=session)

    desired_rse_ids = {rse['id'] for rse in parse_expression(expression=rse_expression, session=session)}
    _sync_rse_transfer_limit(limit_id=limit.id, desired_rse_ids=desired_rse_ids, session=session)
    return limit.id


@transactional_session
def set_transfer_limit_stats(
        limit_id: str,
        waitings: int,
        transfers: int,
        *,
        session: "Session",
):
    """
    Set the statistics of the TransferLimit
    """
    stmt = update(
        models.TransferLimit
    ).where(
        models.TransferLimit.id == limit_id
    ).values(
        waitings=waitings,
        transfers=transfers
    )
    session.execute(stmt)


@transactional_session
def delete_transfer_limit(
        rse_expression: str,
        activity: Optional[str] = None,
        direction: TransferLimitDirection = TransferLimitDirection.DESTINATION,
        *,
        session: "Session",
):

    if activity is None:
        activity = 'all_activities'

    stmt = delete(
        models.RSETransferLimit
    ).where(
        exists(
            select(1)
        ).where(
            models.RSETransferLimit.limit_id == models.TransferLimit.id,
            models.TransferLimit.rse_expression == rse_expression,
            models.TransferLimit.activity == activity,
            models.TransferLimit.direction == direction
        )
    ).execution_options(
        synchronize_session=False
    )
    session.execute(stmt)

    stmt = delete(
        models.TransferLimit
    ).where(
        models.TransferLimit.rse_expression == rse_expression,
        models.TransferLimit.activity == activity,
        models.TransferLimit.direction == direction
    )
    session.execute(stmt)


@transactional_session
def delete_transfer_limit_by_id(
        limit_id: str,
        *,
        session: "Session",
):
    stmt = delete(
        models.RSETransferLimit
    ).where(
        models.RSETransferLimit.limit_id == limit_id
    )
    session.execute(stmt)

    stmt = delete(
        models.TransferLimit
    ).where(
        models.TransferLimit.id == limit_id
    )
    session.execute(stmt)


@transactional_session
def update_requests_priority(priority, filter_, *, session: "Session", logger=logging.log):
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
                update_request(item.id, priority=priority, session=session)
                logger(logging.DEBUG, "Updated request %s priority to %s in rucio." % (item.id, priority))
                if item.request_state == RequestState.SUBMITTED and item.lock_state == LockState.REPLICATING:
                    transfers_to_update.setdefault(item.external_host, {})[item.external_id] = priority
            except Exception:
                logger(logging.DEBUG, "Failed to boost request %s priority: %s" % (item.id, traceback.format_exc()))
        return transfers_to_update
    except IntegrityError as error:
        raise RucioException(error.args)


@read_session
def add_monitor_message(new_state, request, additional_fields, *, session: "Session"):
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


@read_session
def get_source_rse(request_id, src_url, *, session: "Session", logger=logging.log):
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
def list_requests(src_rse_ids, dst_rse_ids, states=None, *, session: "Session"):
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
def list_requests_history(src_rse_ids, dst_rse_ids, states=None, offset=None, limit=None, *, session: "Session"):
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


@transactional_session
def reset_stale_waiting_requests(time_limit: Optional[datetime.timedelta] = datetime.timedelta(days=1), *, session: "Session") -> None:
    """
    Clear source_rse_id for requests that have been in the waiting state for > time_limit amount of time and
    transition back to preparing state (default time limit = 1 day).
    This allows for stale requests that have been in the waiting state for a long time to be able to
    react to source changes that have occurred in the meantime.
    :param time_limit: The amount of time a request must be in the waiting state to be reset.
    :param session: The database session in use.
    """
    try:
        # Cutoff timestamp based on time limit
        time_limit_timestamp = datetime.datetime.utcnow() - time_limit

        # Select all waiting requests that precede the time limit, then clear source_rse_id and reset state to preparing
        stmt = update(
            models.Request
        ).where(
            and_(
                models.Request.state == RequestState.WAITING,
                models.Request.last_processed_at < time_limit_timestamp
            )
        ).execution_options(
            synchronize_session=False
        ).values(
            {
                models.Request.source_rse_id: None,
                models.Request.state: RequestState.PREPARING
            }
        )
        session.execute(stmt)

    except IntegrityError as error:
        raise RucioException(error.args)
