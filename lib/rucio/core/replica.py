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

import copy
import heapq
import logging
import math
import random
from collections import defaultdict, namedtuple
from curses.ascii import isprint
from datetime import datetime, timedelta
from hashlib import sha256
from itertools import groupby
from json import dumps
from re import match
from struct import unpack
from traceback import format_exc
from typing import TYPE_CHECKING, Any, Optional


import requests
from dogpile.cache.api import NO_VALUE
from sqlalchemy import and_, delete, exists, func, insert, not_, or_, union, update
from sqlalchemy.exc import DatabaseError, IntegrityError
from sqlalchemy.orm import aliased
from sqlalchemy.orm.exc import FlushError, NoResultFound
from sqlalchemy.sql.expression import case, false, literal, literal_column, null, select, text, true

import rucio.core.did
import rucio.core.lock
from rucio.common import exception
from rucio.common.cache import MemcacheRegion
from rucio.common.config import config_get, config_get_bool
from rucio.common.constants import RseAttr, SuspiciousAvailability
from rucio.common.types import InternalScope
from rucio.common.utils import add_url_query, chunks, clean_pfns, str_to_date
from rucio.core.credential import get_signed_url
from rucio.core.message import add_messages
from rucio.core.monitor import MetricManager
from rucio.core.rse import get_rse, get_rse_attribute, get_rse_name, get_rse_vo, list_rses
from rucio.core.rse_counter import decrease, increase
from rucio.core.rse_expression_parser import parse_expression
from rucio.db.sqla import filter_thread_work, models
from rucio.db.sqla.constants import OBSOLETE, BadFilesStatus, BadPFNStatus, DIDAvailability, DIDType, ReplicaState, RuleState
from rucio.db.sqla.session import BASE, DEFAULT_SCHEMA_NAME, read_session, stream_session, transactional_session
from rucio.db.sqla.util import temp_table_mngr
from rucio.rse import rsemanager as rsemgr

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Sequence

    from sqlalchemy.orm import Session

    from rucio.common.types import LoggerFunction
    from rucio.rse.protocols.protocol import RSEProtocol

REGION = MemcacheRegion(expiration_time=60)
METRICS = MetricManager(module=__name__)


ScopeName = namedtuple('ScopeName', ['scope', 'name'])
Association = namedtuple('Association', ['scope', 'name', 'child_scope', 'child_name'])


@read_session
def get_bad_replicas_summary(rse_expression=None, from_date=None, to_date=None, filter_=None, *, session: "Session"):
    """
    List the bad file replicas summary. Method used by the rucio-ui.
    :param rse_expression: The RSE expression.
    :param from_date: The start date.
    :param to_date: The end date.
    :param filter_: Dictionary of attributes by which the RSE results should be filtered. e.g.: {'availability_write': True}
    :param session: The database session in use.
    """
    result = []
    incidents = {}
    rse_clause = []
    if rse_expression:
        for rse in parse_expression(expression=rse_expression, filter_=filter_, session=session):
            rse_clause.append(models.BadReplica.rse_id == rse['id'])
    elif filter_:
        # Ensure we limit results to current VO even if we don't specify an RSE expression
        for rse in list_rses(filters=filter_, session=session):
            rse_clause.append(models.BadReplica.rse_id == rse['id'])

    if session.bind.dialect.name == 'oracle':
        to_days = func.trunc(models.BadReplica.created_at, 'DD')
    elif session.bind.dialect.name == 'mysql':
        to_days = func.date(models.BadReplica.created_at)
    elif session.bind.dialect.name == 'postgresql':
        to_days = func.date_trunc('day', models.BadReplica.created_at)
    else:
        to_days = func.strftime(models.BadReplica.created_at, '%Y-%m-%d')

    stmt = select(
        func.count(),
        to_days,
        models.BadReplica.rse_id,
        models.BadReplica.state,
        models.BadReplica.reason
    ).select_from(
        models.BadReplica
    )
    # To be added : HINTS
    if rse_clause != []:
        stmt = stmt.where(or_(*rse_clause))
    if from_date:
        stmt = stmt.where(models.BadReplica.created_at > from_date)
    if to_date:
        stmt = stmt.where(models.BadReplica.created_at < to_date)
    stmt = stmt.group_by(to_days, models.BadReplica.rse_id, models.BadReplica.reason, models.BadReplica.state)
    for count, to_days, rse_id, state, reason in session.execute(stmt):
        if (rse_id, to_days, reason) not in incidents:
            incidents[(rse_id, to_days, reason)] = {}
        incidents[(rse_id, to_days, reason)][str(state.name)] = count

    for incident in incidents:
        res = incidents[incident]
        res['rse_id'] = incident[0]
        res['rse'] = get_rse_name(rse_id=incident[0], session=session)
        res['created_at'] = incident[1]
        res['reason'] = incident[2]
        result.append(res)

    return result


@read_session
def __exist_replicas(rse_id, replicas, *, session: "Session"):
    """
    Internal method to check if a replica exists at a given site.
    :param rse_id: The RSE id.
    :param replicas: A list of tuples [(<scope>, <name>, <path>}) with either :
                     - scope and name are None and path not None
                     - scope and name are not None and path is None
    :param session: The database session in use.

    :returns: A list of tuple (<scope>, <name>, <path>, <exists>, <already_declared>, <bytes>)
              where
              - <exists> is a boolean that identifies if the replica exists
              - <already_declared> is a boolean that identifies if the replica is already declared bad
    """

    return_list = []
    path_clause = []
    did_clause = []
    for scope, name, path in replicas:
        if path:
            path_clause.append(models.RSEFileAssociation.path == path)
            if path.startswith('/'):
                path_clause.append(models.RSEFileAssociation.path == path[1:])
            else:
                path_clause.append(models.RSEFileAssociation.path == '/%s' % path)
        else:
            did_clause.append(and_(models.RSEFileAssociation.scope == scope,
                                   models.RSEFileAssociation.name == name))

    for clause in [path_clause, did_clause]:
        if clause:
            for chunk in chunks(clause, 10):
                stmt = select(
                    models.RSEFileAssociation.path,
                    models.RSEFileAssociation.scope,
                    models.RSEFileAssociation.name,
                    models.RSEFileAssociation.rse_id,
                    models.RSEFileAssociation.bytes,
                    func.max(
                        case(
                            (models.BadReplica.state == BadFilesStatus.SUSPICIOUS, 0),
                            (models.BadReplica.state == BadFilesStatus.BAD, 1),
                            else_=0))
                ).with_hint(
                    models.RSEFileAssociation,
                    'INDEX(REPLICAS REPLICAS_PATH_IDX',
                    'oracle'
                ).outerjoin(
                    models.BadReplica,
                    and_(models.RSEFileAssociation.scope == models.BadReplica.scope,
                         models.RSEFileAssociation.name == models.BadReplica.name,
                         models.RSEFileAssociation.rse_id == models.BadReplica.rse_id)
                ).where(
                    and_(models.RSEFileAssociation.rse_id == rse_id,
                         or_(*chunk))
                ).group_by(
                    models.RSEFileAssociation.path,
                    models.RSEFileAssociation.scope,
                    models.RSEFileAssociation.name,
                    models.RSEFileAssociation.rse_id,
                    models.RSEFileAssociation.bytes
                )

                for path, scope, name, rse_id, size, state in session.execute(stmt).all():
                    if (scope, name, path) in replicas:
                        replicas.remove((scope, name, path))
                    if (None, None, path) in replicas:
                        replicas.remove((None, None, path))
                    if (scope, name, None) in replicas:
                        replicas.remove((scope, name, None))
                    already_declared = False
                    if state == 1:
                        already_declared = True
                    return_list.append((scope, name, path, True, already_declared, size))

    for scope, name, path in replicas:
        return_list.append((scope, name, path, False, False, None))

    return return_list


@read_session
def list_bad_replicas_status(state=BadFilesStatus.BAD, rse_id=None, younger_than=None, older_than=None, limit=None, list_pfns=False, vo='def', *, session: "Session"):
    """
    List the bad file replicas history states. Method used by the rucio-ui.
    :param state: The state of the file (SUSPICIOUS or BAD).
    :param rse_id: The RSE id.
    :param younger_than: datetime object to select bad replicas younger than this date.
    :param older_than:  datetime object to select bad replicas older than this date.
    :param limit: The maximum number of replicas returned.
    :param vo: The VO to find replicas from.
    :param session: The database session in use.
    """
    result = []
    stmt = select(
        models.BadReplica.scope,
        models.BadReplica.name,
        models.BadReplica.rse_id,
        models.BadReplica.state,
        models.BadReplica.created_at,
        models.BadReplica.updated_at
    )
    if state:
        stmt = stmt.where(models.BadReplica.state == state)
    if rse_id:
        stmt = stmt.where(models.BadReplica.rse_id == rse_id)
    if younger_than:
        stmt = stmt.where(models.BadReplica.created_at >= younger_than)
    if older_than:
        stmt = stmt.where(models.BadReplica.created_at <= older_than)
    if limit:
        stmt = stmt.limit(limit)

    for badfile in session.execute(stmt).yield_per(1000):
        if badfile.scope.vo == vo:
            if list_pfns:
                result.append({'scope': badfile.scope, 'name': badfile.name, 'type': DIDType.FILE})
            else:
                result.append({'scope': badfile.scope, 'name': badfile.name, 'rse': get_rse_name(rse_id=badfile.rse_id, session=session), 'rse_id': badfile.rse_id, 'state': badfile.state, 'created_at': badfile.created_at, 'updated_at': badfile.updated_at})
    if list_pfns:
        reps = []
        for rep in list_replicas(result, schemes=None, unavailable=False, request_id=None, ignore_availability=True, all_states=True, session=session):
            pfn = None
            if rse_id in rep['rses'] and rep['rses'][rse_id]:
                pfn = rep['rses'][rse_id][0]
                if pfn and pfn not in reps:
                    reps.append(pfn)
            else:
                reps.extend([item for row in rep['rses'].values() for item in row])
        list(set(reps))
        result = reps
    return result


@transactional_session
def __declare_bad_file_replicas(pfns, rse_id, reason, issuer, status=BadFilesStatus.BAD, scheme='srm', force=False, logger: "LoggerFunction" = logging.log, *, session: "Session"):
    """
    Declare a list of bad replicas.

    :param pfns: Either a list of PFNs (string) or a list of replicas {'scope': <scope>, 'name': <name>, 'rse_id': <rse_id>}.
    :param rse_id: The RSE id.
    :param reason: The reason of the loss.
    :param issuer: The issuer account.
    :param status: Either BAD or SUSPICIOUS.
    :param scheme: The scheme of the PFNs.
    :param force: boolean, if declaring BAD replica, ignore existing replica status in the bad_replicas table. Default: False
    :param session: The database session in use.
    """
    unknown_replicas = []
    replicas = []
    path_pfn_dict = {}

    if len(pfns) > 0 and type(pfns[0]) is str:
        # If pfns is a list of PFNs, the scope and names need to be extracted from the path
        rse_info = rsemgr.get_rse_info(rse_id=rse_id, session=session)
        proto = rsemgr.create_protocol(rse_info, 'read', scheme=scheme)
        if rse_info['deterministic']:
            scope_proto = rsemgr.get_scope_protocol(vo=issuer.vo)
            parsed_pfn = proto.parse_pfns(pfns=pfns)
            for pfn in parsed_pfn:
                # Translate into a scope and name
                name, scope = scope_proto(parsed_pfn[pfn])

                scope = InternalScope(scope, vo=issuer.vo)
                replicas.append({'scope': scope, 'name': name, 'rse_id': rse_id, 'state': status})
                path = '%s%s' % (parsed_pfn[pfn]['path'], parsed_pfn[pfn]['name'])
                path_pfn_dict[path] = pfn
                logger(logging.DEBUG, f"Declaring replica {scope}:{name} {status} at {rse_id} with path {path}")

        else:
            # For non-deterministic RSEs use the path + rse_id to extract the scope
            parsed_pfn = proto.parse_pfns(pfns=pfns)
            for pfn in parsed_pfn:
                path = '%s%s' % (parsed_pfn[pfn]['path'], parsed_pfn[pfn]['name'])
                replicas.append({'scope': None, 'name': None, 'rse_id': rse_id, 'path': path, 'state': status})
                path_pfn_dict[path] = pfn

                logger(logging.DEBUG, f"Declaring replica with pfn: {pfn} {status} at {rse_id} with path {path}")

    else:
        # If pfns is a list of replicas, just use scope, name and rse_id
        for pfn in pfns:
            replicas.append({'scope': pfn['scope'], 'name': pfn['name'], 'rse_id': rse_id, 'state': status})
            logger(logging.DEBUG, f"Declaring replica {pfn['scope']}:{pfn['name']} {status} at {rse_id} without path")

    replicas_list = []
    for replica in replicas:
        scope, name, rse_id, path = replica['scope'], replica['name'], replica['rse_id'], replica.get('path', None)
        replicas_list.append((scope, name, path))

    bad_replicas_to_update = []

    for scope, name, path, __exists, already_declared, size in __exist_replicas(rse_id=rse_id, replicas=replicas_list, session=session):
        declared = False

        if __exists:

            if status == BadFilesStatus.BAD and (force or not already_declared):
                bad_replicas_to_update.append({'scope': scope, 'name': name, 'rse_id': rse_id, 'state': ReplicaState.BAD})
                declared = True

            if status == BadFilesStatus.SUSPICIOUS or status == BadFilesStatus.BAD and not already_declared:
                new_bad_replica = models.BadReplica(scope=scope, name=name, rse_id=rse_id, reason=reason, state=status, account=issuer, bytes=size)
                new_bad_replica.save(session=session, flush=False)
                declared = True

        if not declared:
            if already_declared:
                unknown_replicas.append('%s %s' % (path_pfn_dict.get(path, '%s:%s' % (scope, name)), 'Already declared'))
            elif path:
                no_hidden_char = True
                for char in str(path):
                    if not isprint(char):
                        unknown_replicas.append('%s %s' % (path, 'PFN contains hidden chars'))
                        no_hidden_char = False
                        break
                if no_hidden_char:
                    pfn = path_pfn_dict[path]
                    if f"{pfn} Unknown replica" not in unknown_replicas:
                        unknown_replicas.append('%s %s' % (pfn, 'Unknown replica'))
            elif scope or name:
                unknown_replicas.append(f"{(scope,name)} Unknown replica")

    if status == BadFilesStatus.BAD:
        # For BAD file, we modify the replica state, not for suspicious
        try:
            # there shouldn't be any exceptions since all replicas exist
            update_replicas_states(bad_replicas_to_update, session=session)
        except exception.UnsupportedOperation:
            raise exception.ReplicaNotFound("One or several replicas don't exist.")

    try:
        session.flush()
    except IntegrityError as error:
        raise exception.RucioException(error.args)
    except DatabaseError as error:
        raise exception.RucioException(error.args)
    except FlushError as error:
        raise exception.RucioException(error.args)

    return unknown_replicas


@transactional_session
def add_bad_dids(dids, rse_id, reason, issuer, state=BadFilesStatus.BAD, *, session: "Session"):
    """
    Declare a list of bad replicas.

    :param dids: The list of DIDs.
    :param rse_id: The RSE id.
    :param reason: The reason of the loss.
    :param issuer: The issuer account.
    :param state: BadFilesStatus.BAD
    :param session: The database session in use.
    """
    unknown_replicas = []
    replicas_for_update = []
    replicas_list = []

    for did in dids:
        scope = InternalScope(did['scope'], vo=issuer.vo)
        name = did['name']
        replicas_list.append((scope, name, None))

    for scope, name, _, __exists, already_declared, size in __exist_replicas(rse_id=rse_id, replicas=replicas_list, session=session):
        if __exists and not already_declared:
            replicas_for_update.append({'scope': scope, 'name': name, 'rse_id': rse_id, 'state': ReplicaState.BAD})
            new_bad_replica = models.BadReplica(scope=scope, name=name, rse_id=rse_id, reason=reason, state=state,
                                                account=issuer, bytes=size)
            new_bad_replica.save(session=session, flush=False)
            stmt = delete(
                models.Source
            ).where(
                and_(models.Source.scope == scope,
                     models.Source.name == name,
                     models.Source.rse_id == rse_id)
            ).execution_options(
                synchronize_session=False
            )
            session.execute(stmt)
        else:
            if already_declared:
                unknown_replicas.append('%s:%s %s' % (did['scope'], name, 'Already declared'))
            else:
                unknown_replicas.append('%s:%s %s' % (did['scope'], name, 'Unknown replica'))

    if state == BadFilesStatus.BAD:
        try:
            update_replicas_states(replicas_for_update, session=session)
        except exception.UnsupportedOperation:
            raise exception.ReplicaNotFound("One or several replicas don't exist.")

    try:
        session.flush()
    except (IntegrityError, DatabaseError, FlushError) as error:
        raise exception.RucioException(error.args)

    return unknown_replicas


@transactional_session
def declare_bad_file_replicas(replicas: list, reason: str, issuer, status=BadFilesStatus.BAD, force: bool = False, *,
                              session: "Session"):
    """
    Declare a list of bad replicas.

    :param replicas: Either a list of PFNs (string) or a list of replicas {'scope': <scope>, 'name': <name>, 'rse_id': <rse_id>}.
    :param reason: The reason of the loss.
    :param issuer: The issuer account.
    :param status: The status of the file (SUSPICIOUS or BAD).
    :param force: boolean, if declaring BAD replica, ignore existing replica status in the bad_replicas table. Default: False
    :param session: The database session in use.
    :returns: Dictionary {rse_id -> [replicas failed to declare with errors]}
    """
    unknown_replicas = {}
    if replicas:
        type_ = type(replicas[0])
        files_to_declare = {}
        scheme = None
        for replica in replicas:
            if not isinstance(replica, type_):
                raise exception.InvalidType('Replicas must be specified either as a list of string or a list of dicts')
        if type_ == str:
            scheme, files_to_declare, unknown_replicas = get_pfn_to_rse(replicas, vo=issuer.vo, session=session)
        else:
            for replica in replicas:
                rse_id = replica['rse_id']
                files_to_declare.setdefault(rse_id, []).append(replica)
        for rse_id in files_to_declare:
            notdeclared = __declare_bad_file_replicas(files_to_declare[rse_id], rse_id, reason, issuer,
                                                      status=status, scheme=scheme,
                                                      force=force, session=session)
            if notdeclared:
                unknown_replicas[rse_id] = notdeclared
    return unknown_replicas


@read_session
def get_pfn_to_rse(pfns, vo='def', *, session: "Session"):
    """
    Get the RSE associated to a list of PFNs.

    :param pfns: The list of pfn.
    :param vo: The VO to find RSEs at.
    :param session: The database session in use.

    :returns: a tuple : scheme, {rse1 : [pfn1, pfn2, ...], rse2: [pfn3, pfn4, ...]}, {'unknown': [pfn5, pfn6, ...]}.
    """
    unknown_replicas = {}
    storage_elements = []
    se_condition = []
    dict_rse = {}
    cleaned_pfns = clean_pfns(pfns)
    scheme = cleaned_pfns[0].split(':')[0] if cleaned_pfns else None
    for pfn in cleaned_pfns:
        if pfn.split(':')[0] != scheme:
            raise exception.InvalidType('The PFNs specified must have the same protocol')

        split_se = pfn.split('/')[2].split(':')
        storage_element = split_se[0]

        if storage_element not in storage_elements:
            storage_elements.append(storage_element)
            se_condition.append(models.RSEProtocol.hostname == storage_element)
    stmt = select(
        models.RSEProtocol.rse_id,
        models.RSEProtocol.scheme,
        models.RSEProtocol.hostname,
        models.RSEProtocol.port,
        models.RSEProtocol.prefix
    ).join(
        models.RSE,
        models.RSEProtocol.rse_id == models.RSE.id
    ).where(
        and_(or_(*se_condition),
             models.RSEProtocol.scheme == scheme,
             models.RSE.deleted == false(),
             models.RSE.staging_area == false())
    )

    protocols = {}

    for rse_id, protocol, hostname, port, prefix in session.execute(stmt).yield_per(10000):
        if rse_id not in protocols:
            protocols[rse_id] = []
        protocols[rse_id].append('%s://%s:%s%s' % (protocol, hostname, port, prefix))
        if '%s://%s%s' % (protocol, hostname, prefix) not in protocols[rse_id]:
            protocols[rse_id].append('%s://%s%s' % (protocol, hostname, prefix))
    hint = None
    for pfn in cleaned_pfns:
        if hint:
            for pattern in protocols[hint]:
                if pfn.find(pattern) > -1:
                    dict_rse[hint].append(pfn)
        else:
            mult_rse_match = 0
            for rse_id in protocols:
                for pattern in protocols[rse_id]:
                    if pfn.find(pattern) > -1 and get_rse_vo(rse_id=rse_id, session=session) == vo:
                        mult_rse_match += 1
                        if mult_rse_match > 1:
                            print('ERROR, multiple matches : %s at %s' % (pfn, rse_id))
                            raise exception.RucioException('ERROR, multiple matches : %s at %s' % (pfn, get_rse_name(rse_id=rse_id, session=session)))
                        hint = rse_id
                        if hint not in dict_rse:
                            dict_rse[hint] = []
                        dict_rse[hint].append(pfn)
            if mult_rse_match == 0:
                if 'unknown' not in unknown_replicas:
                    unknown_replicas['unknown'] = []
                unknown_replicas['unknown'].append(pfn)
    return scheme, dict_rse, unknown_replicas


@read_session
def get_bad_replicas_backlog(*, session: "Session"):
    """
    Get the replica backlog by RSE.

    :param session:            The database session in use.

    :returns: a list of dictionary {'rse_id': cnt_bad_replicas}.
    """
    stmt = select(
        func.count(),
        models.RSEFileAssociation.rse_id
    ).select_from(
        models.RSEFileAssociation
    ).with_hint(
        models.RSEFileAssociation,
        'INDEX(DIDS DIDS_PK) USE_NL(DIDS) INDEX_RS_ASC(REPLICAS ("REPLICAS"."STATE"))',
        'oracle'
    ).join(
        models.DataIdentifier,
        and_(models.RSEFileAssociation.scope == models.DataIdentifier.scope,
             models.RSEFileAssociation.name == models.DataIdentifier.name)
    ).where(
        and_(models.DataIdentifier.availability != DIDAvailability.LOST,
             models.RSEFileAssociation.state == ReplicaState.BAD)
    ).group_by(
        models.RSEFileAssociation.rse_id
    )

    result = dict()
    for cnt, rse_id in session.execute(stmt).all():
        result[rse_id] = cnt
    return result


@read_session
def list_bad_replicas(limit=10000, thread=None, total_threads=None, rses=None, *, session: "Session"):
    """
    List RSE File replicas with no locks.

    :param limit: The maximum number of replicas returned.
    :param thread: The assigned thread for this necromancer.
    :param total_threads: The total number of threads of all necromancers.
    :param session: The database session in use.

    :returns: a list of dictionary {'scope' scope, 'name': name, 'rse_id': rse_id, 'rse': rse}.
    """
    schema_dot = '%s.' % DEFAULT_SCHEMA_NAME if DEFAULT_SCHEMA_NAME else ''

    stmt = select(
        models.RSEFileAssociation.scope,
        models.RSEFileAssociation.name,
        models.RSEFileAssociation.rse_id
    ).with_hint(
        models.RSEFileAssociation,
        'INDEX(DIDS DIDS_PK) USE_NL(DIDS) INDEX_RS_ASC(REPLICAS ("REPLICAS"."STATE"))',
        'oracle'
    ).where(
        models.RSEFileAssociation.state == ReplicaState.BAD
    )

    stmt = filter_thread_work(session=session, query=stmt, total_threads=total_threads, thread_id=thread, hash_variable='%sreplicas.name' % (schema_dot))

    stmt = stmt.join(
        models.DataIdentifier,
        and_(models.RSEFileAssociation.scope == models.DataIdentifier.scope,
             models.RSEFileAssociation.name == models.DataIdentifier.name)
    ).where(
        models.DataIdentifier.availability != DIDAvailability.LOST
    )

    if rses:
        rse_clause = [models.RSEFileAssociation.rse_id == rse['id'] for rse in rses]
        stmt = stmt.where(or_(*rse_clause))

    stmt = stmt.limit(limit)
    rows = []
    for scope, name, rse_id in session.execute(stmt).yield_per(1000):
        rows.append({'scope': scope, 'name': name, 'rse_id': rse_id, 'rse': get_rse_name(rse_id=rse_id, session=session)})
    return rows


@stream_session
def get_did_from_pfns(pfns, rse_id=None, vo='def', *, session: "Session"):
    """
    Get the DIDs associated to a PFN on one given RSE

    :param pfns: The list of PFNs.
    :param rse_id: The RSE id.
    :param vo: The VO to get DIDs from.
    :param session: The database session in use.
    :returns: A dictionary {pfn: {'scope': scope, 'name': name}}
    """
    dict_rse = {}
    if not rse_id:
        scheme, dict_rse, unknown_replicas = get_pfn_to_rse(pfns, vo=vo, session=session)
        if unknown_replicas:
            raise Exception
    else:
        scheme = 'srm'
        dict_rse[rse_id] = pfns
    for rse_id in dict_rse:
        pfns = dict_rse[rse_id]
        rse_info = rsemgr.get_rse_info(rse_id=rse_id, session=session)
        pfndict = {}
        proto = rsemgr.create_protocol(rse_info, 'read', scheme=scheme)
        if rse_info['deterministic']:
            scope_proto = rsemgr.get_scope_protocol(vo=vo)
            parsed_pfn = proto.parse_pfns(pfns=pfns)

            for pfn in parsed_pfn:
                # Translate into a scope and name
                name, scope = scope_proto(parsed_pfn[pfn])
                scope = InternalScope(scope, vo)
                yield {pfn: {'scope': scope, 'name': name}}
        else:
            condition = []
            parsed_pfn = proto.parse_pfns(pfns=pfns)
            for pfn in parsed_pfn:
                path = '%s%s' % (parsed_pfn[pfn]['path'], parsed_pfn[pfn]['name'])
                pfndict[path] = pfn
                condition.append(and_(models.RSEFileAssociation.path == path,
                                      models.RSEFileAssociation.rse_id == rse_id))
            stmt = select(
                models.RSEFileAssociation.scope,
                models.RSEFileAssociation.name,
                models.RSEFileAssociation.path
            ).where(
                or_(*condition)
            )
            for scope, name, pfn in session.execute(stmt).all():
                yield {pfndict[pfn]: {'scope': scope, 'name': name}}


def _pick_n_random(nrandom, generator):
    """
    Select n random elements from the generator
    """

    if not nrandom:
        # pass-through the data unchanged
        yield from generator
        return

    # A "reservoir sampling" algorithm:
    # Copy the N first files from the generator. After that, following element may be picked to substitute
    # one of the previously selected element with a probability which decreases as the number of encountered elements grows.
    selected = []
    i = 0
    iterator = iter(generator)
    try:
        for _ in range(nrandom):
            selected.append(next(iterator))
            i += 1

        while True:
            element = next(iterator)
            i += 1

            index_to_substitute = random.randint(0, i)  # noqa: S311
            if index_to_substitute < nrandom:
                selected[index_to_substitute] = element
    except StopIteration:
        pass

    for r in selected:
        yield r


def _list_files_wo_replicas(files_wo_replica, *, session: "Session"):
    if files_wo_replica:
        file_wo_clause = []
        for file in sorted(files_wo_replica, key=lambda f: (f['scope'], f['name'])):
            file_wo_clause.append(and_(models.DataIdentifier.scope == file['scope'],
                                       models.DataIdentifier.name == file['name']))
        stmt = select(
            models.DataIdentifier.scope,
            models.DataIdentifier.name,
            models.DataIdentifier.bytes,
            models.DataIdentifier.md5,
            models.DataIdentifier.adler32
        ).with_hint(
            models.DataIdentifier,
            'INDEX(DIDS DIDS_PK)',
            'oracle'
        ).where(
            and_(models.DataIdentifier.did_type == DIDType.FILE,
                 or_(*file_wo_clause))
        )
        for scope, name, bytes_, md5, adler32 in session.execute(stmt):
            yield scope, name, bytes_, md5, adler32


def get_vp_endpoint():
    """
    VP endpoint is the Virtual Placement server.
    Once VP is integrated in Rucio it won't be needed.
    """
    vp_endpoint = config_get('virtual_placement', 'vp_endpoint', default='')
    return vp_endpoint


def get_multi_cache_prefix(cache_site, filename, logger=logging.log):
    """
    for a givent cache site and filename, return address of the cache node that
    should be prefixed.

    :param cache_site: Cache site
    :param filename:  Filename
    """
    vp_endpoint = get_vp_endpoint()
    if not vp_endpoint:
        return ''

    x_caches = REGION.get('CacheSites')
    if x_caches is NO_VALUE:
        try:
            response = requests.get('{}/serverRanges'.format(vp_endpoint), timeout=1, verify=False)
            if response.ok:
                x_caches = response.json()
                REGION.set('CacheSites', x_caches)
            else:
                REGION.set('CacheSites', {'could not reload': ''})
                return ''
        except requests.exceptions.RequestException as re:
            REGION.set('CacheSites', {'could not reload': ''})
            logger(logging.WARNING, 'In get_multi_cache_prefix, could not access {}. Excaption:{}'.format(vp_endpoint, re))
            return ''

    if cache_site not in x_caches:
        return ''

    xcache_site = x_caches[cache_site]
    h = float(
        unpack('Q', sha256(filename.encode('utf-8')).digest()[:8])[0]) / 2**64
    for irange in xcache_site['ranges']:
        if h < irange[1]:
            return xcache_site['servers'][irange[0]][0]
    return ''


def _get_list_replicas_protocols(
        rse_id: str,
        domain: str,
        schemes: "Sequence[str]",
        additional_schemes: "Sequence[str]",
        session: "Session"
) -> "list[tuple[str, RSEProtocol, int]]":
    """
    Select the protocols to be used by list_replicas to build the PFNs for all replicas on the given RSE
    """
    domains = ['wan', 'lan'] if domain == 'all' else [domain]

    rse_info = rsemgr.get_rse_info(rse_id=rse_id, session=session)
    # compute scheme priorities, and don't forget to exclude disabled protocols
    # 0 or None in RSE protocol definition = disabled, 1 = highest priority
    scheme_priorities = {
        'wan': {p['scheme']: p['domains']['wan']['read'] for p in rse_info['protocols'] if p['domains']['wan']['read']},
        'lan': {p['scheme']: p['domains']['lan']['read'] for p in rse_info['protocols'] if p['domains']['lan']['read']},
    }

    rse_schemes = copy.copy(schemes) if schemes else []
    if not rse_schemes:
        try:
            for domain in domains:
                rse_schemes.append(rsemgr.select_protocol(rse_settings=rse_info,
                                                          operation='read',
                                                          domain=domain)['scheme'])
        except exception.RSEProtocolNotSupported:
            pass  # no need to be verbose
        except Exception:
            print(format_exc())

    for s in additional_schemes:
        if s not in rse_schemes:
            rse_schemes.append(s)

    protocols = []
    for s in rse_schemes:
        try:
            for domain in domains:
                protocol = rsemgr.create_protocol(rse_settings=rse_info, operation='read', scheme=s, domain=domain)
                priority = scheme_priorities[domain][s]

                protocols.append((domain, protocol, priority))
        except exception.RSEProtocolNotSupported:
            pass  # no need to be verbose
        except Exception:
            print(format_exc())
    return protocols


def _build_list_replicas_pfn(
        scope: "InternalScope",
        name: str,
        rse_id: str,
        domain: str,
        protocol: "RSEProtocol",
        path: str,
        sign_urls: bool,
        signature_lifetime: int,
        client_location: "dict[str, Any]",
        logger=logging.log,
        *,
        session: "Session",
) -> str:
    """
    Generate the PFN for the given scope/name on the rse.
    If needed, sign the PFN url
    If relevant, add the server-side root proxy to the pfn url
    """
    pfn: str = list(protocol.lfns2pfns(lfns={'scope': scope.external,
                                             'name': name,
                                             'path': path}).values())[0]

    # do we need to sign the URLs?
    if sign_urls and protocol.attributes['scheme'] == 'https':
        service = get_rse_attribute(rse_id, RseAttr.SIGN_URL, session=session)
        if service:
            pfn = get_signed_url(rse_id=rse_id, service=service, operation='read', url=pfn, lifetime=signature_lifetime)

    # server side root proxy handling if location is set.
    # supports root and http destinations
    # cannot be pushed into protocols because we need to lookup rse attributes.
    # ultra-conservative implementation.
    if domain == 'wan' and protocol.attributes['scheme'] in ['root', 'http', 'https'] and client_location:

        if 'site' in client_location and client_location['site']:
            replica_site = get_rse_attribute(rse_id, RseAttr.SITE, session=session)

            # does it match with the client? if not, it's an outgoing connection
            # therefore the internal proxy must be prepended
            if client_location['site'] != replica_site:
                cache_site = config_get('clientcachemap', client_location['site'], default='', session=session)
                if cache_site != '':
                    # print('client', client_location['site'], 'has cache:', cache_site)
                    # print('filename', name)
                    selected_prefix = get_multi_cache_prefix(cache_site, name)
                    if selected_prefix:
                        pfn = f"root://{selected_prefix}//{pfn.replace('davs://', 'root://')}"
                else:
                    # print('site:', client_location['site'], 'has no cache')
                    # print('lets check if it has defined an internal root proxy ')
                    root_proxy_internal = config_get('root-proxy-internal',    # section
                                                     client_location['site'],  # option
                                                     default='',               # empty string to circumvent exception
                                                     session=session)

                    if root_proxy_internal:
                        # TODO: XCache does not seem to grab signed URLs. Doublecheck with XCache devs.
                        #       For now -> skip prepending XCache for GCS.
                        if 'storage.googleapis.com' in pfn or 'atlas-google-cloud.cern.ch' in pfn or 'amazonaws.com' in pfn:
                            pass  # ATLAS HACK
                        else:
                            # don't forget to mangle gfal-style davs URL into generic https URL
                            pfn = f"root://{root_proxy_internal}//{pfn.replace('davs://', 'https://')}"

    simulate_multirange = get_rse_attribute(rse_id, RseAttr.SIMULATE_MULTIRANGE)

    if simulate_multirange is not None:
        try:
            # cover values that cannot be cast to int
            simulate_multirange = int(simulate_multirange)
        except ValueError:
            simulate_multirange = 1
            logger(logging.WARNING, 'Value encountered when retrieving RSE attribute "%s" not compatible with "int", used default value "1".', RseAttr.SIMULATE_MULTIRANGE)
        if simulate_multirange <= 0:
            logger(logging.WARNING, f'Value {simulate_multirange} encountered when retrieving RSE attribute "{RseAttr.SIMULATE_MULTIRANGE}" is <= 0, used default value "1".')
            simulate_multirange = 1
        pfn += f'&#multirange=false&nconnections={simulate_multirange}'

    return pfn


def _list_replicas(replicas, show_pfns, schemes, files_wo_replica, client_location, domain,
                   sign_urls, signature_lifetime, resolve_parents, filters, by_rse_name, *, session: "Session"):

    # the `domain` variable name will be re-used throughout the function with different values
    input_domain = domain

    # find all RSEs local to the client's location in autoselect mode (i.e., when domain is None)
    local_rses = []
    if input_domain is None:
        if client_location and 'site' in client_location and client_location['site']:
            try:
                local_rses = [rse['id'] for rse in parse_expression('site=%s' % client_location['site'], filter_=filters, session=session)]
            except Exception:
                pass  # do not hard fail if site cannot be resolved or is empty

    file, pfns_cache = {}, {}
    protocols_cache = defaultdict(dict)

    for _, replica_group in groupby(replicas, key=lambda x: (x[0], x[1])):  # Group by scope/name
        file = {}
        pfns = {}
        for scope, name, archive_scope, archive_name, bytes_, md5, adler32, path, state, rse_id, rse, rse_type, volatile in replica_group:
            if isinstance(archive_scope, str):
                archive_scope = InternalScope(archive_scope, fromExternal=False)

            is_archive = bool(archive_scope and archive_name)

            # it is the first row in the scope/name group
            if not file:
                file['scope'], file['name'] = scope, name
                file['bytes'], file['md5'], file['adler32'] = bytes_, md5, adler32
                file['pfns'], file['rses'], file['states'] = {}, {}, {}
                if resolve_parents:
                    file['parents'] = ['%s:%s' % (parent['scope'].internal, parent['name'])
                                       for parent in rucio.core.did.list_all_parent_dids(scope, name, session=session)]

            if not rse_id:
                continue

            rse_key = rse if by_rse_name else rse_id
            file['states'][rse_key] = str(state.name if state else state)

            if not show_pfns:
                continue

            # It's the first time we see this RSE, initialize the protocols needed for PFN generation
            protocols = protocols_cache.get(rse_id, {}).get(is_archive)
            if not protocols:
                # select the lan door in autoselect mode, otherwise use the wan door
                domain = input_domain
                if domain is None:
                    domain = 'wan'
                    if local_rses and rse_id in local_rses:
                        domain = 'lan'

                protocols = _get_list_replicas_protocols(
                    rse_id=rse_id,
                    domain=domain,
                    schemes=schemes,
                    # We want 'root' for archives even if it wasn't included into 'schemes'
                    additional_schemes=['root'] if is_archive else [],
                    session=session,
                )
                protocols_cache[rse_id][is_archive] = protocols

            # build the pfns
            for domain, protocol, priority in protocols:
                # If the current "replica" is a constituent inside an archive, we must construct the pfn for the
                # parent (archive) file and append the xrdcl.unzip query string to it.
                if is_archive:
                    t_scope = archive_scope
                    t_name = archive_name
                else:
                    t_scope = scope
                    t_name = name

                if 'determinism_type' in protocol.attributes:  # PFN is cacheable
                    try:
                        path = pfns_cache['%s:%s:%s' % (protocol.attributes['determinism_type'], t_scope.internal, t_name)]
                    except KeyError:  # No cache entry scope:name found for this protocol
                        path = protocol._get_path(t_scope, t_name)
                        pfns_cache['%s:%s:%s' % (protocol.attributes['determinism_type'], t_scope.internal, t_name)] = path

                try:
                    pfn = _build_list_replicas_pfn(
                        scope=t_scope,
                        name=t_name,
                        rse_id=rse_id,
                        domain=domain,
                        protocol=protocol,
                        path=path,
                        sign_urls=sign_urls,
                        signature_lifetime=signature_lifetime,
                        client_location=client_location,
                        session=session,
                    )

                    client_extract = False
                    if is_archive:
                        domain = 'zip'
                        pfn = add_url_query(pfn, {'xrdcl.unzip': name})
                        if protocol.attributes['scheme'] == 'root':
                            # xroot supports downloading files directly from inside an archive. Disable client_extract and prioritize xroot.
                            client_extract = False
                            priority = -1
                        else:
                            client_extract = True

                    pfns[pfn] = {
                        'rse_id': rse_id,
                        'rse': rse,
                        'type': str(rse_type.name),
                        'volatile': volatile,
                        'domain': domain,
                        'priority': priority,
                        'client_extract': client_extract
                    }

                except Exception:
                    # never end up here
                    print(format_exc())

                if protocol.attributes['scheme'] == 'srm':
                    try:
                        file['space_token'] = protocol.attributes['extended_attributes']['space_token']
                    except KeyError:
                        file['space_token'] = None

        # fill the 'pfns' and 'rses' dicts in file
        if pfns:
            # set the total order for the priority
            # --> exploit that L(AN) comes before W(AN) before Z(IP) alphabetically
            # and use 1-indexing to be compatible with metalink
            sorted_pfns = sorted(pfns.items(), key=lambda item: (item[1]['domain'], item[1]['priority'], item[0]))
            for i, (pfn, pfn_value) in enumerate(list(sorted_pfns), start=1):
                pfn_value['priority'] = i
                file['pfns'][pfn] = pfn_value

            sorted_pfns = sorted(file['pfns'].items(), key=lambda item: (item[1]['rse_id'], item[1]['priority'], item[0]))
            for pfn, pfn_value in sorted_pfns:
                rse_key = pfn_value['rse'] if by_rse_name else pfn_value['rse_id']
                file['rses'].setdefault(rse_key, []).append(pfn)

        if file:
            yield file

    for scope, name, bytes_, md5, adler32 in _list_files_wo_replicas(files_wo_replica, session=session):
        yield {
            'scope': scope,
            'name': name,
            'bytes': bytes_,
            'md5': md5,
            'adler32': adler32,
            'pfns': {},
            'rses': defaultdict(list)
        }


@stream_session
def list_replicas(
        dids: "Sequence[dict[str, Any]]",
        schemes: "Optional[list[str]]" = None,
        unavailable: bool = False,
        request_id: "Optional[str]" = None,
        ignore_availability: bool = True,
        all_states: bool = False,
        pfns: bool = True,
        rse_expression: "Optional[str]" = None,
        client_location: "Optional[dict[str, Any]]" = None,
        domain: "Optional[str]" = None,
        sign_urls: bool = False,
        signature_lifetime: "Optional[int]" = None,
        resolve_archives: bool = True,
        resolve_parents: bool = False,
        nrandom: "Optional[int]" = None,
        updated_after: "Optional[datetime]" = None,
        by_rse_name: bool = False,
        *, session: "Session",
):
    """
    List file replicas for a list of data identifiers (DIDs).

    :param dids: The list of data identifiers (DIDs).
    :param schemes: A list of schemes to filter the replicas. (e.g. file, http, ...)
    :param unavailable: (deprecated) Also include unavailable replicas in the list.
    :param request_id: ID associated with the request for debugging.
    :param ignore_availability: Ignore the RSE blocklisting.
    :param all_states: Return all replicas whatever state they are in. Adds an extra 'states' entry in the result dictionary.
    :param rse_expression: The RSE expression to restrict list_replicas on a set of RSEs.
    :param client_location: Client location dictionary for PFN modification {'ip', 'fqdn', 'site', 'latitude', 'longitude'}
    :param domain: The network domain for the call, either None, 'wan' or 'lan'. None is automatic mode, 'all' is both ['lan','wan']
    :param sign_urls: If set, will sign the PFNs if necessary.
    :param signature_lifetime: If supported, in seconds, restrict the lifetime of the signed PFN.
    :param resolve_archives: When set to true, find archives which contain the replicas.
    :param resolve_parents: When set to true, find all parent datasets which contain the replicas.
    :param updated_after: datetime (UTC time), only return replicas updated after this time
    :param by_rse_name: if True, rse information will be returned in dicts indexed by rse name; otherwise: in dicts indexed by rse id
    :param session: The database session in use.
    """
    # For historical reasons:
    # - list_replicas([some_file_did]), must return the file even if it doesn't have replicas
    # - list_replicas([some_collection_did]) must only return files with replicas

    def _replicas_filter_subquery():
        """
        Build the sub-query used to filter replicas according to list_replica's input arguments
        """
        stmt = select(
            models.RSEFileAssociation.scope,
            models.RSEFileAssociation.name,
            models.RSEFileAssociation.path,
            models.RSEFileAssociation.state,
            models.RSEFileAssociation.bytes,
            models.RSEFileAssociation.md5,
            models.RSEFileAssociation.adler32,
            models.RSE.id.label('rse_id'),
            models.RSE.rse.label('rse_name'),
            models.RSE.rse_type,
            models.RSE.volatile,
        ).join(
            models.RSE,
            and_(models.RSEFileAssociation.rse_id == models.RSE.id,
                 models.RSE.deleted == false())
        )

        if not ignore_availability:
            stmt = stmt.where(models.RSE.availability_read == true())

        if updated_after:
            stmt = stmt.where(models.RSEFileAssociation.updated_at >= updated_after)

        if rse_expression:
            rses = parse_expression(expression=rse_expression, filter_=filter_, session=session)
            # When the number of RSEs is small, don't go through the overhead of
            # creating and using a temporary table. Rely on a simple "in" query.
            # The number "4" was picked without any particular reason
            if 0 < len(rses) < 4:
                stmt = stmt.where(models.RSE.id.in_([rse['id'] for rse in rses]))
            else:
                rses_temp_table = temp_table_mngr(session).create_id_table()
                values = [{'id': rse['id']} for rse in rses]
                insert_stmt = insert(
                    rses_temp_table
                )
                session.execute(insert_stmt, values)
                stmt = stmt.join(rses_temp_table, models.RSE.id == rses_temp_table.id)

        if not all_states:
            if not unavailable:
                state_clause = models.RSEFileAssociation.state == ReplicaState.AVAILABLE
            else:
                state_clause = or_(
                    models.RSEFileAssociation.state == ReplicaState.AVAILABLE,
                    models.RSEFileAssociation.state == ReplicaState.UNAVAILABLE,
                    models.RSEFileAssociation.state == ReplicaState.COPYING
                )
            stmt = stmt.where(state_clause)

        return stmt.subquery()

    def _resolve_collection_files(temp_table, *, session: "Session"):
        """
        Find all FILE dids contained in collections from temp_table and return them in a newly
        created temporary table.
        """
        resolved_files_temp_table = temp_table_mngr(session).create_scope_name_table()
        selectable = rucio.core.did.list_child_dids_stmt(temp_table, did_type=DIDType.FILE)

        stmt = insert(
            resolved_files_temp_table
        ).from_select(
            ['scope', 'name'],
            selectable
        )

        return session.execute(stmt).rowcount, resolved_files_temp_table

    def _list_replicas_for_collection_files_stmt(temp_table, replicas_subquery):
        """
        Build a query for listing replicas of files resolved from containers/datasets

        The query assumes that temp_table only contains DIDs of type FILE.
        """
        return select(
            temp_table.scope.label('scope'),
            temp_table.name.label('name'),
            literal(None).label('archive_scope'),
            literal(None).label('archive_name'),
            replicas_subquery.c.bytes,
            replicas_subquery.c.md5,
            replicas_subquery.c.adler32,
            replicas_subquery.c.path,
            replicas_subquery.c.state,
            replicas_subquery.c.rse_id,
            replicas_subquery.c.rse_name,
            replicas_subquery.c.rse_type,
            replicas_subquery.c.volatile,
        ).join_from(
            temp_table,
            replicas_subquery,
            and_(replicas_subquery.c.scope == temp_table.scope,
                 replicas_subquery.c.name == temp_table.name),
        )

    def _list_replicas_for_constituents_stmt(temp_table, replicas_subquery):
        """
        Build a query for listing replicas of archives containing the files(constituents) given as input.
        i.e. for a file scope:file.log which exists in scope:archive.tar.gz, it will return the replicas
        (rse, path, state, etc) of archive.tar.gz, but with bytes/md5/adler of file.log
        """
        return select(
            models.ConstituentAssociation.child_scope.label('scope'),
            models.ConstituentAssociation.child_name.label('name'),
            models.ConstituentAssociation.scope.label('archive_scope'),
            models.ConstituentAssociation.name.label('archive_name'),
            models.ConstituentAssociation.bytes,
            models.ConstituentAssociation.md5,
            models.ConstituentAssociation.adler32,
            replicas_subquery.c.path,
            replicas_subquery.c.state,
            replicas_subquery.c.rse_id,
            replicas_subquery.c.rse_name,
            replicas_subquery.c.rse_type,
            replicas_subquery.c.volatile,
        ).join_from(
            temp_table,
            models.DataIdentifier,
            and_(models.DataIdentifier.scope == temp_table.scope,
                 models.DataIdentifier.name == temp_table.name,
                 models.DataIdentifier.did_type == DIDType.FILE,
                 models.DataIdentifier.constituent == true()),
        ).join(
            models.ConstituentAssociation,
            and_(models.ConstituentAssociation.child_scope == temp_table.scope,
                 models.ConstituentAssociation.child_name == temp_table.name)
        ).join(
            replicas_subquery,
            and_(replicas_subquery.c.scope == models.ConstituentAssociation.scope,
                 replicas_subquery.c.name == models.ConstituentAssociation.name),
        )

    def _list_replicas_for_input_files_stmt(temp_table, replicas_subquery):
        """
        Builds a query which list the replicas of FILEs from users input, but ignores
        collections in the same input.

        Note: These FILE dids must be returned to the user even if they don't have replicas,
        hence the outerjoin against the replicas_subquery.
        """
        return select(
            temp_table.scope.label('scope'),
            temp_table.name.label('name'),
            literal(None).label('archive_scope'),
            literal(None).label('archive_name'),
            models.DataIdentifier.bytes,
            models.DataIdentifier.md5,
            models.DataIdentifier.adler32,
            replicas_subquery.c.path,
            replicas_subquery.c.state,
            replicas_subquery.c.rse_id,
            replicas_subquery.c.rse_name,
            replicas_subquery.c.rse_type,
            replicas_subquery.c.volatile,
        ).join_from(
            temp_table,
            models.DataIdentifier,
            and_(models.DataIdentifier.scope == temp_table.scope,
                 models.DataIdentifier.name == temp_table.name,
                 models.DataIdentifier.did_type == DIDType.FILE),
        ).outerjoin(
            replicas_subquery,
            and_(replicas_subquery.c.scope == temp_table.scope,
                 replicas_subquery.c.name == temp_table.name),
        )

    def _inspect_dids(temp_table, *, session: "Session"):
        """
        Find how many files, collections and constituents are among the dids in the temp_table
        """
        stmt = select(
            func.sum(
                case((models.DataIdentifier.did_type == DIDType.FILE, 1), else_=0)
            ).label('num_files'),
            func.sum(
                case((models.DataIdentifier.did_type.in_([DIDType.CONTAINER, DIDType.DATASET]), 1), else_=0)
            ).label('num_collections'),
            func.sum(
                case((models.DataIdentifier.constituent == true(), 1), else_=0)
            ).label('num_constituents'),
        ).join_from(
            temp_table,
            models.DataIdentifier,
            and_(models.DataIdentifier.scope == temp_table.scope,
                 models.DataIdentifier.name == temp_table.name),
        )
        num_files, num_collections, num_constituents = session.execute(stmt).one()  # returns None on empty input
        return num_files or 0, num_collections or 0, num_constituents or 0

    if dids:
        filter_ = {'vo': dids[0]['scope'].vo}
    else:
        filter_ = {'vo': 'def'}

    dids = {(did['scope'], did['name']): did for did in dids}  # Deduplicate input
    if not dids:
        return

    input_dids_temp_table = temp_table_mngr(session).create_scope_name_table()
    values = [{'scope': scope, 'name': name} for scope, name in dids]
    stmt = insert(
        input_dids_temp_table
    )
    session.execute(stmt, values)

    num_files, num_collections, num_constituents = _inspect_dids(input_dids_temp_table, session=session)

    num_files_in_collections, resolved_files_temp_table = 0, None
    if num_collections:
        num_files_in_collections, resolved_files_temp_table = _resolve_collection_files(input_dids_temp_table, session=session)

    replicas_subquery = _replicas_filter_subquery()
    replica_sources = []
    if num_files:
        replica_sources.append(
            _list_replicas_for_input_files_stmt(input_dids_temp_table, replicas_subquery)
        )
    if num_constituents and resolve_archives:
        replica_sources.append(
            _list_replicas_for_constituents_stmt(input_dids_temp_table, replicas_subquery)
        )
    if num_files_in_collections:
        replica_sources.append(
            _list_replicas_for_collection_files_stmt(resolved_files_temp_table, replicas_subquery)
        )

    if not replica_sources:
        return

    # In the simple case that somebody calls list_replicas on big collections with nrandom set,
    # opportunistically try to reduce the number of fetched and analyzed rows.
    if (
            nrandom
            # Only try this optimisation if list_replicas was called on collection(s).
            # I didn't consider handling the case when list_replica is called with a mix of
            # file/archive/collection dids: database queries in those cases are more complex
            # and people don't usually call list_replicas with nrandom on file/archive_constituents anyway.
            and (num_files_in_collections and not num_constituents and not num_files)
            # The following code introduces overhead if it fails to pick n random replicas.
            # Only execute when nrandom is much smaller than the total number of candidate files.
            # 64 was picked without any particular reason as "seems good enough".
            and 0 < nrandom < num_files_in_collections / 64
    ):
        # Randomly select a subset of file DIDs which have at least one replica matching the RSE/replica
        # filters applied on database side. Some filters are applied later in python code
        # (for example: scheme; or client_location/domain). We don't have any guarantee that
        # those, python, filters will not drop the replicas which we just selected randomly.
        stmt = select(
            resolved_files_temp_table.scope.label('scope'),
            resolved_files_temp_table.name.label('name'),
        ).where(
            exists(
                select(1)
            ).where(
                replicas_subquery.c.scope == resolved_files_temp_table.scope,
                replicas_subquery.c.name == resolved_files_temp_table.name
            )
        ).order_by(
            literal_column('dbms_random.value') if session.bind.dialect.name == 'oracle' else func.random()
        ).limit(
            # slightly overshoot to reduce the probability that python-side filtering will
            # leave us with less than nrandom replicas.
            nrandom * 4
        )
        # Reuse input temp table. We don't need its content anymore
        random_dids_temp_table = input_dids_temp_table
        session.execute(delete(random_dids_temp_table))
        stmt = insert(
            random_dids_temp_table
        ).from_select(
            ['scope', 'name'],
            stmt
        )
        session.execute(stmt)

        # Fetch all replicas for randomly selected dids and apply filters on python side
        stmt = _list_replicas_for_collection_files_stmt(random_dids_temp_table, replicas_subquery)
        stmt = stmt.order_by('scope', 'name')
        replica_tuples = session.execute(stmt)
        random_replicas = list(
            _pick_n_random(
                nrandom,
                _list_replicas(replica_tuples, pfns, schemes, [], client_location, domain,
                               sign_urls, signature_lifetime, resolve_parents, filter_, by_rse_name, session=session)
            )
        )
        if len(random_replicas) == nrandom:
            yield from random_replicas
            return
        else:
            # Our opportunistic attempt to pick nrandom replicas without fetching all database rows failed,
            # continue with the normal list_replicas flow and fetch all replicas
            pass

    if len(replica_sources) == 1:
        stmt = replica_sources[0].order_by('scope', 'name')
        replica_tuples = session.execute(stmt)
    else:
        if session.bind.dialect.name == 'mysql':
            # On mysql, perform both queries independently and merge their result in python.
            # The union query fails with "Can't reopen table"
            replica_tuples = heapq.merge(
                *[session.execute(stmt.order_by('scope', 'name')) for stmt in replica_sources],
                key=lambda t: (t[0], t[1]),  # sort by scope, name
            )
        else:
            stmt = union(*replica_sources).order_by('scope', 'name')
            replica_tuples = session.execute(stmt)

    yield from _pick_n_random(
        nrandom,
        _list_replicas(replica_tuples, pfns, schemes, [], client_location, domain,
                       sign_urls, signature_lifetime, resolve_parents, filter_, by_rse_name, session=session)
    )


@transactional_session
def __bulk_add_new_file_dids(files, account, dataset_meta=None, *, session: "Session"):
    """
    Bulk add new dids.

    :param dids: the list of new files.
    :param account: The account owner.
    :param session: The database session in use.
    :returns: True is successful.
    """
    for file in files:
        new_did = models.DataIdentifier(scope=file['scope'], name=file['name'],
                                        account=file.get('account') or account,
                                        did_type=DIDType.FILE, bytes=file['bytes'],
                                        md5=file.get('md5'), adler32=file.get('adler32'),
                                        is_new=None)
        new_did.save(session=session, flush=False)

        if 'meta' in file and file['meta']:
            rucio.core.did.set_metadata_bulk(scope=file['scope'], name=file['name'], meta=file['meta'], recursive=False, session=session)
        if dataset_meta:
            rucio.core.did.set_metadata_bulk(scope=file['scope'], name=file['name'], meta=dataset_meta, recursive=False, session=session)
    try:
        session.flush()
    except IntegrityError as error:
        if match('.*IntegrityError.*02291.*integrity constraint.*DIDS_SCOPE_FK.*violated - parent key not found.*', error.args[0]) \
                or match('.*IntegrityError.*FOREIGN KEY constraint failed.*', error.args[0]) \
                or match('.*IntegrityError.*1452.*Cannot add or update a child row: a foreign key constraint fails.*', error.args[0]) \
                or match('.*IntegrityError.*02291.*integrity constraint.*DIDS_SCOPE_FK.*violated - parent key not found.*', error.args[0]) \
                or match('.*IntegrityError.*insert or update on table.*violates foreign key constraint "DIDS_SCOPE_FK".*', error.args[0]) \
                or match('.*ForeignKeyViolation.*insert or update on table.*violates foreign key constraint.*', error.args[0]) \
                or match('.*IntegrityError.*foreign key constraints? failed.*', error.args[0]):
            raise exception.ScopeNotFound('Scope not found!')

        raise exception.RucioException(error.args)
    except DatabaseError as error:
        if match('.*(DatabaseError).*ORA-14400.*inserted partition key does not map to any partition.*', error.args[0]):
            raise exception.ScopeNotFound('Scope not found!')

        raise exception.RucioException(error.args)
    except FlushError as error:
        if match('New instance .* with identity key .* conflicts with persistent instance', error.args[0]):
            raise exception.DataIdentifierAlreadyExists('Data Identifier already exists!')
        raise exception.RucioException(error.args)
    return True


@transactional_session
def __bulk_add_file_dids(files, account, dataset_meta=None, *, session: "Session"):
    """
    Bulk add new dids.

    :param dids: the list of files.
    :param account: The account owner.
    :param session: The database session in use.
    :returns: list of replicas.
    """
    condition = []
    for f in files:
        condition.append(and_(models.DataIdentifier.scope == f['scope'],
                              models.DataIdentifier.name == f['name'],
                              models.DataIdentifier.did_type == DIDType.FILE))

    stmt = select(
        models.DataIdentifier.scope,
        models.DataIdentifier.name,
        models.DataIdentifier.bytes,
        models.DataIdentifier.md5,
        models.DataIdentifier.adler32,
    ).with_hint(
        models.DataIdentifier,
        'INDEX(DIDS DIDS_PK)',
        'oracle'
    ).where(
        or_(*condition)
    )
    available_files = [res._asdict() for res in session.execute(stmt).all()]
    new_files = list()
    for file in files:
        found = False
        for available_file in available_files:
            if file['scope'] == available_file['scope'] and file['name'] == available_file['name']:
                found = True
                break
        if not found:
            new_files.append(file)
    __bulk_add_new_file_dids(files=new_files, account=account,
                             dataset_meta=dataset_meta,
                             session=session)
    return new_files + available_files


def tombstone_from_delay(tombstone_delay):
    # Tolerate None for tombstone_delay
    if not tombstone_delay:
        return None

    tombstone_delay = timedelta(seconds=int(tombstone_delay))

    if not tombstone_delay:
        return None

    if tombstone_delay < timedelta(0):
        return datetime(1970, 1, 1)

    return datetime.utcnow() + tombstone_delay


@transactional_session
def __bulk_add_replicas(rse_id, files, account, *, session: "Session"):
    """
    Bulk add new dids.

    :param rse_id: the RSE id.
    :param dids: the list of files.
    :param account: The account owner.
    :param session: The database session in use.
    :returns: True is successful.
    """
    nbfiles, bytes_ = 0, 0
    # Check for the replicas already available
    condition = []
    for f in files:
        condition.append(and_(models.RSEFileAssociation.scope == f['scope'],
                              models.RSEFileAssociation.name == f['name'],
                              models.RSEFileAssociation.rse_id == rse_id))

    stmt = select(
        models.RSEFileAssociation.scope,
        models.RSEFileAssociation.name,
        models.RSEFileAssociation.rse_id,
    ).with_hint(
        models.RSEFileAssociation,
        'INDEX(REPLICAS REPLICAS_PK)',
        'oracle'
    ).where(
        or_(*condition)
    )

    available_replicas = [res._asdict() for res in session.execute(stmt).all()]

    default_tombstone_delay = get_rse_attribute(rse_id, RseAttr.TOMBSTONE_DELAY, session=session)
    default_tombstone = tombstone_from_delay(default_tombstone_delay)

    new_replicas = []
    for file in files:
        found = False
        for available_replica in available_replicas:
            if file['scope'] == available_replica['scope'] and file['name'] == available_replica['name'] and rse_id == available_replica['rse_id']:
                found = True
                break
        if not found:
            nbfiles += 1
            bytes_ += file['bytes']
            new_replicas.append({'rse_id': rse_id, 'scope': file['scope'],
                                 'name': file['name'], 'bytes': file['bytes'],
                                 'path': file.get('path'),
                                 'state': ReplicaState(file.get('state', 'A')),
                                 'md5': file.get('md5'), 'adler32': file.get('adler32'),
                                 'lock_cnt': file.get('lock_cnt', 0),
                                 'tombstone': file.get('tombstone') or default_tombstone})
    try:
        stmt = insert(
            models.RSEFileAssociation
        )
        new_replicas and session.execute(stmt, new_replicas)
        session.flush()
        return nbfiles, bytes_
    except IntegrityError as error:
        if match('.*IntegrityError.*ORA-00001: unique constraint .*REPLICAS_PK.*violated.*', error.args[0]) \
                or match('.*IntegrityError.*1062.*Duplicate entry.*', error.args[0]) \
                or match('.*IntegrityError.*columns? rse_id.*scope.*name.*not unique.*', error.args[0]) \
                or match('.*IntegrityError.*duplicate key value violates unique constraint.*', error.args[0]):
            raise exception.Duplicate("File replica already exists!")
        raise exception.RucioException(error.args)
    except DatabaseError as error:
        raise exception.RucioException(error.args)


@transactional_session
def add_replicas(rse_id, files, account, ignore_availability=True,
                 dataset_meta=None, *, session: "Session"):
    """
    Bulk add file replicas.

    :param rse_id:  The RSE id.
    :param files:   The list of files.
    :param account: The account owner.
    :param ignore_availability: Ignore the RSE blocklisting.
    :param session: The database session in use.

    :returns: list of replicas.
    """

    def _expected_pfns(lfns, rse_settings, scheme, operation='write', domain='wan', protocol_attr=None):
        p = rsemgr.create_protocol(rse_settings=rse_settings, operation='write', scheme=scheme, domain=domain, protocol_attr=protocol_attr)
        expected_pfns = p.lfns2pfns(lfns)
        return clean_pfns(expected_pfns.values())

    replica_rse = get_rse(rse_id=rse_id, session=session)

    if replica_rse['volatile'] is True:
        raise exception.UnsupportedOperation('Cannot add replicas on volatile RSE %s ' % (replica_rse['rse']))

    if not replica_rse['availability_write'] and not ignore_availability:
        raise exception.ResourceTemporaryUnavailable('%s is temporary unavailable for writing' % replica_rse['rse'])

    for file in files:
        if 'pfn' not in file:
            if not replica_rse['deterministic']:
                raise exception.UnsupportedOperation('PFN needed for this (non deterministic) RSE %s ' % (replica_rse['rse']))

    __bulk_add_file_dids(files=files, account=account,
                         dataset_meta=dataset_meta,
                         session=session)

    pfns = {}  # dict[str, list[str]], {scheme: [pfns], scheme: [pfns]}
    for file in files:
        if 'pfn' in file:
            scheme = file['pfn'].split(':')[0]
            pfns.setdefault(scheme, []).append(file['pfn'])

    if pfns:
        rse_settings = rsemgr.get_rse_info(rse_id=rse_id, session=session)
        for scheme in pfns.keys():
            if not replica_rse['deterministic']:
                p = rsemgr.create_protocol(rse_settings=rse_settings, operation='write', scheme=scheme)
                pfns[scheme] = p.parse_pfns(pfns=pfns[scheme])
                for file in files:
                    if file['pfn'].startswith(scheme):
                        tmp = pfns[scheme][file['pfn']]
                        file['path'] = ''.join([tmp['path'], tmp['name']])
            else:
                # Check that the pfns match to the expected pfns
                lfns = [{'scope': i['scope'].external, 'name': i['name']} for i in files if i['pfn'].startswith(scheme)]
                pfns[scheme] = clean_pfns(pfns[scheme])

                for protocol_attr in rsemgr.get_protocols_ordered(rse_settings=rse_settings, operation='write', scheme=scheme, domain='wan'):
                    pfns[scheme] = list(set(pfns[scheme]) - set(_expected_pfns(lfns, rse_settings, scheme, operation='write', domain='wan', protocol_attr=protocol_attr)))

                if len(pfns[scheme]) > 0:
                    for protocol_attr in rsemgr.get_protocols_ordered(rse_settings=rse_settings, operation='write', scheme=scheme, domain='lan'):
                        pfns[scheme] = list(set(pfns[scheme]) - set(_expected_pfns(lfns, rse_settings, scheme, operation='write', domain='lan', protocol_attr=protocol_attr)))

                if len(pfns[scheme]) > 0:
                    # pfns not found in wan or lan
                    raise exception.InvalidPath('One of the PFNs provided does not match the Rucio expected PFN : %s (%s)' % (str(pfns[scheme]), str(lfns)))

    nbfiles, bytes_ = __bulk_add_replicas(rse_id=rse_id, files=files, account=account, session=session)
    increase(rse_id=rse_id, files=nbfiles, bytes_=bytes_, session=session)


@transactional_session
def add_replica(
    rse_id: str,
    scope: InternalScope,
    name: str,
    bytes_: int,
    account: models.InternalAccount,
    adler32: "Optional[str]" = None,
    md5: "Optional[str]" = None,
    dsn: "Optional[str]" = None,
    pfn: "Optional[str]" = None,
    meta: "Optional[dict[str, Any]]" = None,
    rules: "Optional[list[dict[str, Any]]]" = None,
    tombstone: "Optional[datetime]" = None,
    *,
    session: "Session"
) -> "list[dict[str, Any]]":
    """
    Add File replica.

    :param rse_id: the rse id.
    :param scope: the scope name.
    :param name: The data identifier name.
    :param bytes_: the size of the file.
    :param account: The account owner.
    :param md5: The md5 checksum.
    :param adler32: The adler32 checksum.
    :param pfn: Physical file name (for nondeterministic rse).
    :param meta: Meta-data associated with the file. Represented as key/value pairs in a dictionary.
    :param rules: Replication rules associated with the file. A list of dictionaries, e.g., [{'copies': 2, 'rse_expression': 'TIERS1'}, ].
    :param tombstone: If True, create replica with a tombstone.
    :param session: The database session in use.

    :returns: list of replicas.
    """
    meta = meta or {}
    rules = rules or []

    file = {'scope': scope, 'name': name, 'bytes': bytes_, 'adler32': adler32, 'md5': md5, 'meta': meta, 'rules': rules, 'tombstone': tombstone}
    if pfn:
        file['pfn'] = pfn
    return add_replicas(rse_id=rse_id, files=[file, ], account=account, session=session)


@METRICS.time_it
@transactional_session
def delete_replicas(rse_id, files, ignore_availability=True, *, session: "Session"):
    """
    Delete file replicas.

    :param rse_id: the rse id.
    :param files: the list of files to delete.
    :param ignore_availability: Ignore the RSE blocklisting.
    :param session: The database session in use.
    """
    if not files:
        return

    replica_rse = get_rse(rse_id=rse_id, session=session)

    if not replica_rse['availability_delete'] and not ignore_availability:
        raise exception.ResourceTemporaryUnavailable('%s is temporary unavailable'
                                                     'for deleting' % replica_rse['rse'])
    tt_mngr = temp_table_mngr(session)
    scope_name_temp_table = tt_mngr.create_scope_name_table()
    scope_name_temp_table2 = tt_mngr.create_scope_name_table()
    association_temp_table = tt_mngr.create_association_table()

    values = [{'scope': file['scope'], 'name': file['name']} for file in files]
    stmt = insert(
        scope_name_temp_table
    )
    session.execute(stmt, values)

    # WARNING : This should not be necessary since that would mean the replica is used as a source.
    stmt = delete(
        models.Source,
    ).where(
        exists(select(1)
               .where(and_(models.Source.scope == scope_name_temp_table.scope,
                           models.Source.name == scope_name_temp_table.name,
                           models.Source.rse_id == rse_id)))
    ).execution_options(
        synchronize_session=False
    )
    session.execute(stmt)

    stmt = select(
        func.count(),
        func.sum(models.RSEFileAssociation.bytes),
    ).join_from(
        scope_name_temp_table,
        models.RSEFileAssociation,
        and_(models.RSEFileAssociation.scope == scope_name_temp_table.scope,
             models.RSEFileAssociation.name == scope_name_temp_table.name,
             models.RSEFileAssociation.rse_id == rse_id)
    )
    delta, bytes_ = session.execute(stmt).one()

    # Delete replicas
    stmt = delete(
        models.RSEFileAssociation,
    ).where(
        exists(select(1)
               .where(
                   and_(models.RSEFileAssociation.scope == scope_name_temp_table.scope,
                        models.RSEFileAssociation.name == scope_name_temp_table.name,
                        models.RSEFileAssociation.rse_id == rse_id)))
    ).execution_options(
        synchronize_session=False
    )
    res = session.execute(stmt)
    if res.rowcount != len(files):
        raise exception.ReplicaNotFound("One or several replicas don't exist.")

    # Update bad replicas
    stmt = update(
        models.BadReplica,
    ).where(
        exists(select(1)
               .where(
                   and_(models.BadReplica.scope == scope_name_temp_table.scope,
                        models.BadReplica.name == scope_name_temp_table.name,
                        models.BadReplica.rse_id == rse_id)))
    ).where(
        models.BadReplica.state == BadFilesStatus.BAD
    ).values({
        models.BadReplica.state: BadFilesStatus.DELETED,
        models.BadReplica.updated_at: datetime.utcnow()
    }).execution_options(
        synchronize_session=False
    )

    res = session.execute(stmt)

    __cleanup_after_replica_deletion(scope_name_temp_table=scope_name_temp_table,
                                     scope_name_temp_table2=scope_name_temp_table2,
                                     association_temp_table=association_temp_table,
                                     rse_id=rse_id, files=files, session=session)

    # Decrease RSE counter
    decrease(rse_id=rse_id, files=delta, bytes_=bytes_, session=session)


@transactional_session
def __cleanup_after_replica_deletion(scope_name_temp_table, scope_name_temp_table2, association_temp_table, rse_id, files, *, session: "Session"):
    """
    Perform update of collections/archive associations/dids after the removal of their replicas
    :param rse_id: the rse id
    :param files: list of files whose replica got deleted
    :param session: The database session in use.
    """
    clt_to_update, parents_to_analyze, affected_archives, clt_replicas_to_delete = set(), set(), set(), set()
    did_condition = []
    incomplete_dids, messages, clt_to_set_not_archive = [], [], []
    for file in files:

        # Schedule update of all collections containing this file and having a collection replica in the RSE
        clt_to_update.add(ScopeName(scope=file['scope'], name=file['name']))

        # If the file doesn't have any replicas anymore, we should perform cleanups of objects
        # related to this file. However, if the file is "lost", it's removal wasn't intentional,
        # so we want to skip deleting the metadata here. Perform cleanups:

        # 1) schedule removal of this file from all parent datasets
        parents_to_analyze.add(ScopeName(scope=file['scope'], name=file['name']))

        # 2) schedule removal of this file from the DID table
        did_condition.append(
            and_(models.DataIdentifier.scope == file['scope'],
                 models.DataIdentifier.name == file['name'],
                 models.DataIdentifier.availability != DIDAvailability.LOST,
                 ~exists(select(1).prefix_with("/*+ INDEX(REPLICAS REPLICAS_PK) */", dialect='oracle')).where(
                     and_(models.RSEFileAssociation.scope == file['scope'],
                          models.RSEFileAssociation.name == file['name'])),
                 ~exists(select(1).prefix_with("/*+ INDEX(ARCHIVE_CONTENTS ARCH_CONTENTS_PK) */", dialect='oracle')).where(
                     and_(models.ConstituentAssociation.child_scope == file['scope'],
                          models.ConstituentAssociation.child_name == file['name']))))

        # 3) if the file is an archive, schedule cleanup on the files from inside the archive
        affected_archives.add(ScopeName(scope=file['scope'], name=file['name']))

    if clt_to_update:
        # Get all collection_replicas at RSE, insert them into UpdatedCollectionReplica
        stmt = delete(scope_name_temp_table)
        session.execute(stmt)
        values = [sn._asdict() for sn in clt_to_update]
        stmt = insert(scope_name_temp_table)
        session.execute(stmt, values)
        stmt = select(
            models.DataIdentifierAssociation.scope,
            models.DataIdentifierAssociation.name,
        ).distinct(
        ).join_from(
            scope_name_temp_table,
            models.DataIdentifierAssociation,
            and_(scope_name_temp_table.scope == models.DataIdentifierAssociation.child_scope,
                 scope_name_temp_table.name == models.DataIdentifierAssociation.child_name)
        ).join(
            models.CollectionReplica,
            and_(models.CollectionReplica.scope == models.DataIdentifierAssociation.scope,
                 models.CollectionReplica.name == models.DataIdentifierAssociation.name,
                 models.CollectionReplica.rse_id == rse_id)
        )
        for parent_scope, parent_name in session.execute(stmt):
            models.UpdatedCollectionReplica(scope=parent_scope,
                                            name=parent_name,
                                            did_type=DIDType.DATASET,
                                            rse_id=rse_id). \
                save(session=session, flush=False)

    # Delete did from the content for the last did
    while parents_to_analyze:
        did_associations_to_remove = set()

        stmt = delete(scope_name_temp_table)
        session.execute(stmt)
        values = [sn._asdict() for sn in parents_to_analyze]
        stmt = insert(scope_name_temp_table)
        session.execute(stmt, values)
        parents_to_analyze.clear()

        stmt = select(
            models.DataIdentifierAssociation.scope,
            models.DataIdentifierAssociation.name,
            models.DataIdentifierAssociation.did_type,
            models.DataIdentifierAssociation.child_scope,
            models.DataIdentifierAssociation.child_name,
        ).distinct(
        ).join_from(
            scope_name_temp_table,
            models.DataIdentifierAssociation,
            and_(scope_name_temp_table.scope == models.DataIdentifierAssociation.child_scope,
                 scope_name_temp_table.name == models.DataIdentifierAssociation.child_name)
        ).outerjoin(
            models.DataIdentifier,
            and_(models.DataIdentifier.availability == DIDAvailability.LOST,
                 models.DataIdentifier.scope == models.DataIdentifierAssociation.child_scope,
                 models.DataIdentifier.name == models.DataIdentifierAssociation.child_name)
        ).where(
            models.DataIdentifier.scope == null()
        ).outerjoin(
            models.RSEFileAssociation,
            and_(models.RSEFileAssociation.scope == models.DataIdentifierAssociation.child_scope,
                 models.RSEFileAssociation.name == models.DataIdentifierAssociation.child_name)
        ).where(
            models.RSEFileAssociation.scope == null()
        ).outerjoin(
            models.ConstituentAssociation,
            and_(models.ConstituentAssociation.child_scope == models.DataIdentifierAssociation.child_scope,
                 models.ConstituentAssociation.child_name == models.DataIdentifierAssociation.child_name)
        ).where(
            models.ConstituentAssociation.child_scope == null()
        )

        clt_to_set_not_archive.append(set())
        for parent_scope, parent_name, did_type, child_scope, child_name in session.execute(stmt):

            # Schedule removal of child file/dataset/container from the parent dataset/container
            did_associations_to_remove.add(Association(scope=parent_scope, name=parent_name,
                                                       child_scope=child_scope, child_name=child_name))

            # Schedule setting is_archive = False on parents which don't have any children with is_archive == True anymore
            clt_to_set_not_archive[-1].add(ScopeName(scope=parent_scope, name=parent_name))

            # If the parent dataset/container becomes empty as a result of the child removal
            # (it was the last children), metadata cleanup has to be done:
            #
            # 1) Schedule to remove the replicas of this empty collection
            clt_replicas_to_delete.add(ScopeName(scope=parent_scope, name=parent_name))

            # 2) Schedule removal of this empty collection from its own parent collections
            parents_to_analyze.add(ScopeName(scope=parent_scope, name=parent_name))

            # 3) Schedule removal of the entry from the DIDs table
            remove_open_did = config_get_bool('reaper', 'remove_open_did', default=False, session=session)
            if remove_open_did:
                did_condition.append(
                    and_(models.DataIdentifier.scope == parent_scope,
                         models.DataIdentifier.name == parent_name,
                         ~exists(1).where(
                             and_(models.DataIdentifierAssociation.child_scope == parent_scope,
                                  models.DataIdentifierAssociation.child_name == parent_name)),
                         ~exists(1).where(
                             and_(models.DataIdentifierAssociation.scope == parent_scope,
                                  models.DataIdentifierAssociation.name == parent_name))))
            else:
                did_condition.append(
                    and_(models.DataIdentifier.scope == parent_scope,
                         models.DataIdentifier.name == parent_name,
                         models.DataIdentifier.is_open == false(),
                         ~exists(1).where(
                             and_(models.DataIdentifierAssociation.child_scope == parent_scope,
                                  models.DataIdentifierAssociation.child_name == parent_name)),
                         ~exists(1).where(
                             and_(models.DataIdentifierAssociation.scope == parent_scope,
                                  models.DataIdentifierAssociation.name == parent_name))))

        if did_associations_to_remove:
            stmt = delete(association_temp_table)
            session.execute(stmt)
            values = [a._asdict() for a in did_associations_to_remove]
            stmt = insert(association_temp_table)
            session.execute(stmt, values)

            # get the list of modified parent scope, name
            stmt = select(
                models.DataIdentifier.scope,
                models.DataIdentifier.name,
                models.DataIdentifier.did_type,
            ).distinct(
            ).join_from(
                association_temp_table,
                models.DataIdentifier,
                and_(association_temp_table.scope == models.DataIdentifier.scope,
                     association_temp_table.name == models.DataIdentifier.name)
            ).where(
                or_(models.DataIdentifier.complete == true(),
                    models.DataIdentifier.complete.is_(None)),
            )
            for parent_scope, parent_name, parent_did_type in session.execute(stmt):
                message = {'scope': parent_scope,
                           'name': parent_name,
                           'did_type': parent_did_type,
                           'event_type': 'INCOMPLETE'}
                if message not in messages:
                    messages.append(message)
                    incomplete_dids.append(ScopeName(scope=parent_scope, name=parent_name))

            content_to_delete_filter = exists(select(1)
                                              .where(and_(association_temp_table.scope == models.DataIdentifierAssociation.scope,
                                                          association_temp_table.name == models.DataIdentifierAssociation.name,
                                                          association_temp_table.child_scope == models.DataIdentifierAssociation.child_scope,
                                                          association_temp_table.child_name == models.DataIdentifierAssociation.child_name)))

            rucio.core.did.insert_content_history(filter_=content_to_delete_filter, did_created_at=None, session=session)

            stmt = delete(
                models.DataIdentifierAssociation
            ).where(
                content_to_delete_filter,
            ).execution_options(
                synchronize_session=False
            )
            session.execute(stmt)

    # Get collection replicas of collections which became empty
    if clt_replicas_to_delete:
        stmt = delete(scope_name_temp_table)
        session.execute(stmt)
        values = [sn._asdict() for sn in clt_replicas_to_delete]
        stmt = insert(scope_name_temp_table)
        session.execute(stmt, values)
        stmt = delete(scope_name_temp_table2)
        session.execute(stmt)
        stmt = select(
            models.CollectionReplica.scope,
            models.CollectionReplica.name,
        ).distinct(
        ).join_from(
            scope_name_temp_table,
            models.CollectionReplica,
            and_(scope_name_temp_table.scope == models.CollectionReplica.scope,
                 scope_name_temp_table.name == models.CollectionReplica.name),
        ).join(
            models.DataIdentifier,
            and_(models.DataIdentifier.scope == models.CollectionReplica.scope,
                 models.DataIdentifier.name == models.CollectionReplica.name)
        ).outerjoin(
            models.DataIdentifierAssociation,
            and_(models.DataIdentifierAssociation.scope == models.CollectionReplica.scope,
                 models.DataIdentifierAssociation.name == models.CollectionReplica.name)
        ).where(
            models.DataIdentifierAssociation.scope == null()
        )
        stmt = insert(
            scope_name_temp_table2
        ).from_select(
            ['scope', 'name'],
            stmt
        )
        session.execute(stmt)
        # Delete the retrieved collection replicas of empty collections
        stmt = delete(
            models.CollectionReplica,
        ).where(
            exists(select(1)
                   .where(and_(models.CollectionReplica.scope == scope_name_temp_table2.scope,
                               models.CollectionReplica.name == scope_name_temp_table2.name)))
        ).execution_options(
            synchronize_session=False
        )
        session.execute(stmt)

    # Update incomplete state
    messages, dids_to_delete = [], set()
    if incomplete_dids:
        stmt = delete(scope_name_temp_table)
        session.execute(stmt)
        values = [sn._asdict() for sn in incomplete_dids]
        stmt = insert(scope_name_temp_table)
        session.execute(stmt, values)
        stmt = update(
            models.DataIdentifier
        ).where(
            exists(select(1)
                   .where(and_(models.DataIdentifier.scope == scope_name_temp_table.scope,
                               models.DataIdentifier.name == scope_name_temp_table.name)))
        ).where(
            models.DataIdentifier.complete != false(),
        ).values({
            models.DataIdentifier.complete: False
        }).execution_options(
            synchronize_session=False
        )

        session.execute(stmt)

    # delete empty dids
    if did_condition:
        for chunk in chunks(did_condition, 10):
            stmt = select(
                models.DataIdentifier.scope,
                models.DataIdentifier.name,
                models.DataIdentifier.did_type,
            ).with_hint(
                models.DataIdentifier,
                'INDEX(DIDS DIDS_PK)',
                'oracle'
            ).where(
                or_(*chunk)
            )
            for scope, name, did_type in session.execute(stmt):
                if did_type == DIDType.DATASET:
                    messages.append({'event_type': 'ERASE',
                                     'payload': dumps({'scope': scope.external,
                                                       'name': name,
                                                       'account': 'root'})})
                dids_to_delete.add(ScopeName(scope=scope, name=name))

    # Remove Archive Constituents
    constituent_associations_to_delete = set()
    if affected_archives:
        stmt = delete(scope_name_temp_table)
        session.execute(stmt)
        values = [sn._asdict() for sn in affected_archives]
        stmt = insert(scope_name_temp_table)
        session.execute(stmt, values)

        stmt = select(
            models.ConstituentAssociation
        ).distinct(
        ).join_from(
            scope_name_temp_table,
            models.ConstituentAssociation,
            and_(scope_name_temp_table.scope == models.ConstituentAssociation.scope,
                 scope_name_temp_table.name == models.ConstituentAssociation.name),
        ).outerjoin(
            models.DataIdentifier,
            and_(models.DataIdentifier.availability == DIDAvailability.LOST,
                 models.DataIdentifier.scope == models.ConstituentAssociation.scope,
                 models.DataIdentifier.name == models.ConstituentAssociation.name)
        ).where(
            models.DataIdentifier.scope == null()
        ).outerjoin(
            models.RSEFileAssociation,
            and_(models.RSEFileAssociation.scope == models.ConstituentAssociation.scope,
                 models.RSEFileAssociation.name == models.ConstituentAssociation.name)
        ).where(
            models.RSEFileAssociation.scope == null()
        )

        for constituent in session.execute(stmt).scalars().all():
            constituent_associations_to_delete.add(Association(scope=constituent.scope, name=constituent.name,
                                                               child_scope=constituent.child_scope, child_name=constituent.child_name))
            models.ConstituentAssociationHistory(
                child_scope=constituent.child_scope,
                child_name=constituent.child_name,
                scope=constituent.scope,
                name=constituent.name,
                bytes=constituent.bytes,
                adler32=constituent.adler32,
                md5=constituent.md5,
                guid=constituent.guid,
                length=constituent.length,
                updated_at=constituent.updated_at,
                created_at=constituent.created_at,
            ).save(session=session, flush=False)

    if constituent_associations_to_delete:
        stmt = delete(association_temp_table)
        session.execute(stmt)
        values = [a._asdict() for a in constituent_associations_to_delete]
        stmt = insert(association_temp_table)
        session.execute(stmt, values)
        stmt = delete(
            models.ConstituentAssociation
        ).where(
            exists(select(1)
                   .where(and_(association_temp_table.scope == models.ConstituentAssociation.scope,
                               association_temp_table.name == models.ConstituentAssociation.name,
                               association_temp_table.child_scope == models.ConstituentAssociation.child_scope,
                               association_temp_table.child_name == models.ConstituentAssociation.child_name)))
        ).execution_options(
            synchronize_session=False
        )
        session.execute(stmt)

        removed_constituents = {ScopeName(scope=c.child_scope, name=c.child_name) for c in constituent_associations_to_delete}
        for chunk in chunks(removed_constituents, 200):
            __cleanup_after_replica_deletion(scope_name_temp_table=scope_name_temp_table,
                                             scope_name_temp_table2=scope_name_temp_table2,
                                             association_temp_table=association_temp_table,
                                             rse_id=rse_id, files=[sn._asdict() for sn in chunk], session=session)

    if dids_to_delete:
        stmt = delete(scope_name_temp_table)
        session.execute(stmt)
        values = [sn._asdict() for sn in dids_to_delete]
        stmt = insert(scope_name_temp_table)
        session.execute(stmt, values)

        # Remove rules in Waiting for approval or Suspended
        stmt = delete(
            models.ReplicationRule,
        ).where(
            exists(select(1)
                   .where(and_(models.ReplicationRule.scope == scope_name_temp_table.scope,
                               models.ReplicationRule.name == scope_name_temp_table.name)))
        ).where(
            models.ReplicationRule.state.in_((RuleState.SUSPENDED, RuleState.WAITING_APPROVAL))
        ).execution_options(
            synchronize_session=False
        )
        session.execute(stmt)

        # Remove DID Metadata
        must_delete_did_meta = True
        if session.bind.dialect.name == 'oracle':
            oracle_version = int(session.connection().connection.version.split('.')[0])
            if oracle_version < 12:
                must_delete_did_meta = False
        if must_delete_did_meta:
            stmt = delete(
                models.DidMeta,
            ).where(
                exists(select(1)
                       .where(and_(models.DidMeta.scope == scope_name_temp_table.scope,
                                   models.DidMeta.name == scope_name_temp_table.name)))
            ).execution_options(
                synchronize_session=False
            )
            session.execute(stmt)

        for chunk in chunks(messages, 100):
            add_messages(chunk, session=session)

        # Delete dids
        dids_to_delete_filter = exists(select(1)
                                       .where(and_(models.DataIdentifier.scope == scope_name_temp_table.scope,
                                                   models.DataIdentifier.name == scope_name_temp_table.name)))
        archive_dids = config_get_bool('deletion', 'archive_dids', default=False, session=session)
        if archive_dids:
            rucio.core.did.insert_deleted_dids(filter_=dids_to_delete_filter, session=session)
        stmt = delete(
            models.DataIdentifier,
        ).where(
            dids_to_delete_filter,
        ).execution_options(
            synchronize_session=False
        )
        session.execute(stmt)

    # Set is_archive = false on collections which don't have archive children anymore
    while clt_to_set_not_archive:
        to_update = clt_to_set_not_archive.pop(0)
        if not to_update:
            continue
        stmt = delete(scope_name_temp_table)
        session.execute(stmt)
        values = [sn._asdict() for sn in to_update]
        stmt = insert(scope_name_temp_table)
        session.execute(stmt, values)
        stmt = delete(scope_name_temp_table2)
        session.execute(stmt)

        data_identifier_alias = aliased(models.DataIdentifier, name='did_alias')
        # Fetch rows to be updated
        stmt = select(
            models.DataIdentifier.scope,
            models.DataIdentifier.name,
        ).distinct(
        ).where(
            models.DataIdentifier.is_archive == true()
        ).join_from(
            scope_name_temp_table,
            models.DataIdentifier,
            and_(scope_name_temp_table.scope == models.DataIdentifier.scope,
                 scope_name_temp_table.name == models.DataIdentifier.name)
        ).join(
            models.DataIdentifierAssociation,
            and_(models.DataIdentifier.scope == models.DataIdentifierAssociation.scope,
                 models.DataIdentifier.name == models.DataIdentifierAssociation.name)
        ).outerjoin(
            data_identifier_alias,
            and_(data_identifier_alias.scope == models.DataIdentifierAssociation.child_scope,
                 data_identifier_alias.name == models.DataIdentifierAssociation.child_name,
                 data_identifier_alias.is_archive == true())
        ).where(
            data_identifier_alias.scope == null()
        )
        stmt = insert(
            scope_name_temp_table2
        ).from_select(
            ['scope', 'name'],
            stmt
        )
        session.execute(stmt)
        # update the fetched rows
        stmt = update(
            models.DataIdentifier,
        ).where(
            exists(select(1)
                   .where(and_(models.DataIdentifier.scope == scope_name_temp_table2.scope,
                               models.DataIdentifier.name == scope_name_temp_table2.name)))
        ).values({
            models.DataIdentifier.is_archive: False
        }).execution_options(
            synchronize_session=False
        )
        session.execute(stmt)


@transactional_session
def get_replica(rse_id, scope, name, *, session: "Session"):
    """
    Get File replica.

    :param rse_id: The RSE Id.
    :param scope: the scope name.
    :param name: The data identifier name.
    :param session: The database session in use.

    :returns: A dictionary with the list of replica attributes.
    """
    try:
        stmt = select(
            models.RSEFileAssociation
        ).where(
            and_(models.RSEFileAssociation.scope == scope,
                 models.RSEFileAssociation.name == name,
                 models.RSEFileAssociation.rse_id == rse_id)
        )
        return session.execute(stmt).scalar_one().to_dict()
    except NoResultFound:
        raise exception.ReplicaNotFound("No row found for scope: %s name: %s rse: %s" % (scope, name, get_rse_name(rse_id=rse_id, session=session)))

@transactional_session
def list_and_mark_unlocked_replicas(limit, bytes_=None, rse_id=None, delay_seconds=600, only_delete_obsolete=False, *, session: "Session"):
    """
    List RSE File replicas with no locks.

    :param limit:                    Number of replicas returned.
    :param bytes_:                   The amount of needed bytes.
    :param rse_id:                   The rse_id.
    :param delay_seconds:            The delay to query replicas in BEING_DELETED state, default is 10 minutes
    :param only_delete_obsolete      If set to True, will only return the replicas with EPOCH tombstone
    :param session:                  The database session in use.

    :returns: a list of dictionary replica.
    """

    needed_space = bytes_
    total_bytes = 0
    rows = []

    temp_table_cls = temp_table_mngr(session).create_scope_name_table()

    replicas_alias = aliased(models.RSEFileAssociation, name='replicas_alias')

    stmt = select(
        models.RSEFileAssociation.scope,
        models.RSEFileAssociation.name,
    ).where(
        models.RSEFileAssociation.lock_cnt == 0,
        models.RSEFileAssociation.rse_id == rse_id,
        models.RSEFileAssociation.tombstone == OBSOLETE if only_delete_obsolete else models.RSEFileAssociation.tombstone < datetime.utcnow(),
    ).where(
        or_(models.RSEFileAssociation.state.in_((ReplicaState.AVAILABLE, ReplicaState.UNAVAILABLE, ReplicaState.BAD)),
            and_(models.RSEFileAssociation.state == ReplicaState.BEING_DELETED, models.RSEFileAssociation.updated_at < datetime.utcnow() - timedelta(seconds=delay_seconds)))
    ).outerjoin(
        models.Source,
        and_(models.RSEFileAssociation.scope == models.Source.scope,
             models.RSEFileAssociation.name == models.Source.name,
             models.RSEFileAssociation.rse_id == models.Source.rse_id)
    ).where(
        models.Source.scope.is_(None)  # Only try to delete replicas if they are not used as sources in any transfers
    ).order_by(
        models.RSEFileAssociation.tombstone,
        models.RSEFileAssociation.updated_at
    ).with_for_update(
        skip_locked=True,
        # oracle: we must specify a column, not a table; however, it doesn't matter which column, the lock is put on the whole row
        # postgresql/mysql: sqlalchemy driver automatically converts it to a table name
        # sqlite: this is completely ignored
        of=models.RSEFileAssociation.scope,
    )

    for chunk in chunks(session.execute(stmt).yield_per(2 * limit), math.ceil(1.25 * limit)):
        stmt = delete(temp_table_cls)
        session.execute(stmt)
        values = [{'scope': scope, 'name': name} for scope, name in chunk]
        stmt = insert(temp_table_cls)
        session.execute(stmt, values)

        stmt = select(
            models.RSEFileAssociation.scope,
            models.RSEFileAssociation.name,
            models.RSEFileAssociation.path,
            models.RSEFileAssociation.bytes,
            models.RSEFileAssociation.tombstone,
            models.RSEFileAssociation.state,
            models.DataIdentifier.datatype,
        ).join_from(
            temp_table_cls,
            models.RSEFileAssociation,
            and_(models.RSEFileAssociation.scope == temp_table_cls.scope,
                 models.RSEFileAssociation.name == temp_table_cls.name,
                 models.RSEFileAssociation.rse_id == rse_id)
        ).with_hint(
            replicas_alias,
            'INDEX(%(name)s REPLICAS_PK)',
            'oracle'
        ).outerjoin(
            replicas_alias,
            and_(models.RSEFileAssociation.scope == replicas_alias.scope,
                 models.RSEFileAssociation.name == replicas_alias.name,
                 models.RSEFileAssociation.rse_id != replicas_alias.rse_id,
                 replicas_alias.state == ReplicaState.AVAILABLE)
        ).with_hint(
            models.Request,
            'INDEX(requests REQUESTS_SCOPE_NAME_RSE_IDX)',
            'oracle'
        ).outerjoin(
            models.Request,
            and_(models.RSEFileAssociation.scope == models.Request.scope,
                 models.RSEFileAssociation.name == models.Request.name)
        ).join(
            models.DataIdentifier,
            and_(models.RSEFileAssociation.scope == models.DataIdentifier.scope,
                 models.RSEFileAssociation.name == models.DataIdentifier.name)
        ).group_by(
            models.RSEFileAssociation.scope,
            models.RSEFileAssociation.name,
            models.RSEFileAssociation.path,
            models.RSEFileAssociation.bytes,
            models.RSEFileAssociation.tombstone,
            models.RSEFileAssociation.state,
            models.RSEFileAssociation.updated_at,
            models.DataIdentifier.datatype
        ).having(
            case((func.count(replicas_alias.scope) > 0, True),  # Can delete this replica if it's not the last replica
                 (func.count(models.Request.scope) == 0, True),  # If it's the last replica, only can delete if there are no requests using it
                 else_=False).label("can_delete"),
        ).order_by(
            models.RSEFileAssociation.tombstone,
            models.RSEFileAssociation.updated_at
        ).limit(
            limit - len(rows)
        )

        for scope, name, path, bytes_, tombstone, state, datatype in session.execute(stmt):
            if len(rows) >= limit or (not only_delete_obsolete and needed_space is not None and total_bytes > needed_space):
                break
            if state != ReplicaState.UNAVAILABLE:
                total_bytes += bytes_

            rows.append({'scope': scope, 'name': name, 'path': path,
                         'bytes': bytes_, 'tombstone': tombstone,
                         'state': state, 'datatype': datatype})
        if len(rows) >= limit or (not only_delete_obsolete and needed_space is not None and total_bytes > needed_space):
            break

    if rows:
        stmt = delete(temp_table_cls)
        session.execute(stmt)
        values = [{'scope': row['scope'], 'name': row['name']} for row in rows]
        stmt = insert(temp_table_cls)
        session.execute(stmt, values)
        stmt = update(
            models.RSEFileAssociation
        ).where(
            exists(select(1).prefix_with("/*+ INDEX(REPLICAS REPLICAS_PK) */", dialect='oracle')
                   .where(and_(models.RSEFileAssociation.scope == temp_table_cls.scope,
                               models.RSEFileAssociation.name == temp_table_cls.name,
                               models.RSEFileAssociation.rse_id == rse_id)))
        ).values({
            models.RSEFileAssociation.updated_at: datetime.utcnow(),
            models.RSEFileAssociation.state: ReplicaState.BEING_DELETED,
            models.RSEFileAssociation.tombstone: OBSOLETE
        }).execution_options(
            synchronize_session=False
        )

        session.execute(stmt)

    return rows


@transactional_session
def update_replicas_states(replicas, nowait=False, *, session: "Session"):
    """
    Update File replica information and state.

    :param replicas:        The list of replicas.
    :param nowait:          Nowait parameter for the for_update queries.
    :param session:         The database session in use.
    """

    for replica in replicas:
        stmt = select(
            models.RSEFileAssociation
        ).where(
            models.RSEFileAssociation.rse_id == replica['rse_id'],
            models.RSEFileAssociation.scope == replica['scope'],
            models.RSEFileAssociation.name == replica['name']
        ).with_for_update(
            nowait=nowait
        )

        if session.execute(stmt).scalar_one_or_none() is None:
            # remember scope, name and rse
            raise exception.ReplicaNotFound("No row found for scope: %s name: %s rse: %s" % (replica['scope'], replica['name'], get_rse_name(replica['rse_id'], session=session)))

        if isinstance(replica['state'], str):
            replica['state'] = ReplicaState(replica['state'])

        values = {'state': replica['state']}
        if replica['state'] == ReplicaState.BEING_DELETED:
            # Exclude replicas use as sources
            stmt = stmt.where(
                and_(models.RSEFileAssociation.lock_cnt == 0,
                     not_(exists(select(1)
                                 .where(and_(models.RSEFileAssociation.scope == models.Source.scope,
                                             models.RSEFileAssociation.name == models.Source.name,
                                             models.RSEFileAssociation.rse_id == models.Source.rse_id)))))
            )
            values['tombstone'] = OBSOLETE
        elif replica['state'] == ReplicaState.AVAILABLE:
            rucio.core.lock.successful_transfer(scope=replica['scope'], name=replica['name'], rse_id=replica['rse_id'], nowait=nowait, session=session)
            stmt_bad_replicas = select(
                func.count()
            ).select_from(
                models.BadReplica
            ).where(
                and_(models.BadReplica.state == BadFilesStatus.BAD,
                     models.BadReplica.rse_id == replica['rse_id'],
                     models.BadReplica.scope == replica['scope'],
                     models.BadReplica.name == replica['name'])
            )

            if session.execute(stmt_bad_replicas).scalar():
                update_stmt = update(
                    models.BadReplica
                ).where(
                    and_(models.BadReplica.state == BadFilesStatus.BAD,
                         models.BadReplica.rse_id == replica['rse_id'],
                         models.BadReplica.scope == replica['scope'],
                         models.BadReplica.name == replica['name'])
                ).values({
                    models.BadReplica.state: BadFilesStatus.RECOVERED,
                    models.BadReplica.updated_at: datetime.utcnow()
                }).execution_options(
                    synchronize_session=False
                )
                session.execute(update_stmt)
        elif replica['state'] == ReplicaState.UNAVAILABLE:
            rucio.core.lock.failed_transfer(scope=replica['scope'], name=replica['name'], rse_id=replica['rse_id'],
                                            error_message=replica.get('error_message', None),
                                            broken_rule_id=replica.get('broken_rule_id', None),
                                            broken_message=replica.get('broken_message', None),
                                            nowait=nowait, session=session)
        elif replica['state'] == ReplicaState.TEMPORARY_UNAVAILABLE:
            stmt = stmt.where(
                models.RSEFileAssociation.state.in_([ReplicaState.AVAILABLE,
                                                     ReplicaState.TEMPORARY_UNAVAILABLE])
            )

        if 'path' in replica and replica['path']:
            values['path'] = replica['path']

        update_stmt = update(
            models.RSEFileAssociation
        ).where(
            and_(models.RSEFileAssociation.rse_id == replica['rse_id'],
                 models.RSEFileAssociation.scope == replica['scope'],
                 models.RSEFileAssociation.name == replica['name'])
        ).values(
            values
        ).execution_options(
            synchronize_session=False
        )

        if not session.execute(update_stmt).rowcount:
            if 'rse' not in replica:
                replica['rse'] = get_rse_name(rse_id=replica['rse_id'], session=session)
            raise exception.UnsupportedOperation('State %(state)s for replica %(scope)s:%(name)s on %(rse)s cannot be updated' % replica)
    return True


@transactional_session
def touch_replica(replica, *, session: "Session"):
    """
    Update the accessed_at timestamp of the given file replica/did but don't wait if row is locked.

    :param replica: a dictionary with the information of the affected replica.
    :param session: The database session in use.

    :returns: True, if successful, False otherwise.
    """
    try:
        accessed_at, none_value = replica.get('accessed_at') or datetime.utcnow(), None

        stmt = select(
            models.RSEFileAssociation
        ).with_hint(
            models.RSEFileAssociation,
            'INDEX(REPLICAS REPLICAS_PK)',
            'oracle'
        ).where(
            and_(models.RSEFileAssociation.rse_id == replica['rse_id'],
                 models.RSEFileAssociation.scope == replica['scope'],
                 models.RSEFileAssociation.name == replica['name'])
        ).with_for_update(
            nowait=True
        )
        session.execute(stmt).one()

        stmt = update(
            models.RSEFileAssociation
        ).where(
            and_(models.RSEFileAssociation.rse_id == replica['rse_id'],
                 models.RSEFileAssociation.scope == replica['scope'],
                 models.RSEFileAssociation.name == replica['name'])
        ).prefix_with(
            '/*+ INDEX(REPLICAS REPLICAS_PK) */', dialect='oracle'
        ).values({
            models.RSEFileAssociation.accessed_at: accessed_at,
            models.RSEFileAssociation.tombstone: case(
                (models.RSEFileAssociation.tombstone.not_in([OBSOLETE, none_value]),
                 accessed_at),
                else_=models.RSEFileAssociation.tombstone)
        }).execution_options(
            synchronize_session=False
        )
        session.execute(stmt)

        stmt = select(
            models.DataIdentifier
        ).with_hint(
            models.DataIdentifier,
            'INDEX(DIDS DIDS_PK)',
            'oracle'
        ).where(
            and_(models.DataIdentifier.scope == replica['scope'],
                 models.DataIdentifier.name == replica['name'],
                 models.DataIdentifier.did_type == DIDType.FILE)
        ).with_for_update(
            nowait=True
        )
        session.execute(stmt).one()

        stmt = update(
            models.DataIdentifier
        ).where(
            and_(models.DataIdentifier.scope == replica['scope'],
                 models.DataIdentifier.name == replica['name'],
                 models.DataIdentifier.did_type == DIDType.FILE)
        ).prefix_with(
            '/*+ INDEX(DIDS DIDS_PK) */', dialect='oracle'
        ).values({
            models.DataIdentifier.accessed_at: accessed_at
        }).execution_options(
            synchronize_session=False
        )
        session.execute(stmt)

    except DatabaseError:
        return False
    except NoResultFound:
        return True

    return True


@transactional_session
def update_replica_state(rse_id, scope, name, state, *, session: "Session"):
    """
    Update File replica information and state.

    :param rse_id: the rse id.
    :param scope: the tag name.
    :param name: The data identifier name.
    :param state: The state.
    :param session: The database session in use.
    """
    return update_replicas_states(replicas=[{'scope': scope, 'name': name, 'state': state, 'rse_id': rse_id}], session=session)


@transactional_session
def get_and_lock_file_replicas(scope, name, nowait=False, restrict_rses=None, *, session: "Session"):
    """
    Get file replicas for a specific scope:name.

    :param scope:          The scope of the did.
    :param name:           The name of the did.
    :param nowait:         Nowait parameter for the FOR UPDATE statement
    :param restrict_rses:  Possible RSE_ids to filter on.
    :param session:        The db session in use.
    :returns:              List of SQLAlchemy Replica Objects
    """

    stmt = select(
        models.RSEFileAssociation
    ).where(
        and_(models.RSEFileAssociation.scope == scope,
             models.RSEFileAssociation.name == name,
             models.RSEFileAssociation.state != ReplicaState.BEING_DELETED)
    ).with_for_update(
        nowait=nowait
    )
    if restrict_rses is not None and len(restrict_rses) < 10:
        rse_clause = [models.RSEFileAssociation.rse_id == rse_id for rse_id in restrict_rses]
        if rse_clause:
            stmt = stmt.where(or_(*rse_clause))

    return session.execute(stmt).scalars().all()


@transactional_session
def get_source_replicas(scope, name, source_rses=None, *, session: "Session"):
    """
    Get source replicas for a specific scope:name.

    :param scope:          The scope of the did.
    :param name:           The name of the did.
    :param soruce_rses:    Possible RSE_ids to filter on.
    :param session:        The db session in use.
    :returns:              List of SQLAlchemy Replica Objects
    """

    stmt = select(
        models.RSEFileAssociation.rse_id
    ).where(
        and_(models.RSEFileAssociation.scope == scope,
             models.RSEFileAssociation.name == name,
             models.RSEFileAssociation.state == ReplicaState.AVAILABLE)
    )
    if source_rses:
        if len(source_rses) < 10:
            rse_clause = []
            for rse_id in source_rses:
                rse_clause.append(models.RSEFileAssociation.rse_id == rse_id)
            if rse_clause:
                stmt = stmt.where(or_(*rse_clause))
    return session.execute(stmt).scalars().all()


@transactional_session
def get_and_lock_file_replicas_for_dataset(scope, name, nowait=False, restrict_rses=None,
                                           total_threads=None, thread_id=None,
                                           *, session: "Session"):
    """
    Get file replicas for all files of a dataset.

    :param scope:          The scope of the dataset.
    :param name:           The name of the dataset.
    :param nowait:         Nowait parameter for the FOR UPDATE statement
    :param restrict_rses:  Possible RSE_ids to filter on.
    :param total_threads:  Total threads
    :param thread_id:      This thread
    :param session:        The db session in use.
    :returns:              (files in dataset, replicas in dataset)
    """
    files, replicas = {}, {}

    base_stmt = select(
        models.DataIdentifierAssociation.child_scope,
        models.DataIdentifierAssociation.child_name,
        models.DataIdentifierAssociation.bytes,
        models.DataIdentifierAssociation.md5,
        models.DataIdentifierAssociation.adler32,
    ).where(
        and_(models.DataIdentifierAssociation.scope == scope,
             models.DataIdentifierAssociation.name == name)
    )

    stmt = base_stmt.add_columns(
        models.RSEFileAssociation
    ).where(
        and_(models.DataIdentifierAssociation.child_scope == models.RSEFileAssociation.scope,
             models.DataIdentifierAssociation.child_name == models.RSEFileAssociation.name,
             models.RSEFileAssociation.state != ReplicaState.BEING_DELETED)
    )

    rse_clause = [true()]
    if restrict_rses is not None and len(restrict_rses) < 10:
        rse_clause = [models.RSEFileAssociation.rse_id == rse_id for rse_id in restrict_rses]

    if session.bind.dialect.name == 'postgresql':
        if total_threads and total_threads > 1:
            base_stmt = filter_thread_work(session=session,
                                           query=base_stmt,
                                           total_threads=total_threads,
                                           thread_id=thread_id,
                                           hash_variable='child_name')

        for child_scope, child_name, bytes_, md5, adler32 in session.execute(base_stmt).yield_per(1000):
            files[(child_scope, child_name)] = {'scope': child_scope,
                                                'name': child_name,
                                                'bytes': bytes_,
                                                'md5': md5,
                                                'adler32': adler32}
            replicas[(child_scope, child_name)] = []

        stmt = stmt.where(or_(*rse_clause))
    else:
        stmt = base_stmt.add_columns(
            models.RSEFileAssociation
        ).with_hint(
            models.DataIdentifierAssociation,
            'INDEX_RS_ASC(CONTENTS CONTENTS_PK) NO_INDEX_FFS(CONTENTS CONTENTS_PK)',
            'oracle'
        ).outerjoin(
            models.RSEFileAssociation,
            and_(models.DataIdentifierAssociation.child_scope == models.RSEFileAssociation.scope,
                 models.DataIdentifierAssociation.child_name == models.RSEFileAssociation.name,
                 models.RSEFileAssociation.state != ReplicaState.BEING_DELETED,
                 or_(*rse_clause))
        )

    if total_threads and total_threads > 1:
        stmt = filter_thread_work(session=session,
                                  query=stmt,
                                  total_threads=total_threads,
                                  thread_id=thread_id,
                                  hash_variable='child_name')

    stmt = stmt.with_for_update(
        nowait=nowait,
        of=models.RSEFileAssociation.lock_cnt
    )

    for child_scope, child_name, bytes_, md5, adler32, replica in session.execute(stmt).yield_per(1000):
        if (child_scope, child_name) not in files:
            files[(child_scope, child_name)] = {'scope': child_scope,
                                                'name': child_name,
                                                'bytes': bytes_,
                                                'md5': md5,
                                                'adler32': adler32}

        if (child_scope, child_name) in replicas:
            if replica is not None:
                replicas[(child_scope, child_name)].append(replica)
        else:
            replicas[(child_scope, child_name)] = []
            if replica is not None:
                replicas[(child_scope, child_name)].append(replica)

    return (list(files.values()), replicas)


@transactional_session
def get_source_replicas_for_dataset(scope, name, source_rses=None,
                                    total_threads=None, thread_id=None,
                                    *, session: "Session"):
    """
    Get file replicas for all files of a dataset.

    :param scope:          The scope of the dataset.
    :param name:           The name of the dataset.
    :param source_rses:    Possible source RSE_ids to filter on.
    :param total_threads:  Total threads
    :param thread_id:      This thread
    :param session:        The db session in use.
    :returns:              (files in dataset, replicas in dataset)
    """
    stmt = select(
        models.DataIdentifierAssociation.child_scope,
        models.DataIdentifierAssociation.child_name,
        models.RSEFileAssociation.rse_id
    ).with_hint(
        models.DataIdentifierAssociation,
        'INDEX_RS_ASC(CONTENTS CONTENTS_PK) NO_INDEX_FFS(CONTENTS CONTENTS_PK)',
        'oracle'
    ).outerjoin(
        models.RSEFileAssociation,
        and_(models.DataIdentifierAssociation.child_scope == models.RSEFileAssociation.scope,
             models.DataIdentifierAssociation.child_name == models.RSEFileAssociation.name,
             models.RSEFileAssociation.state == ReplicaState.AVAILABLE)
    ).where(
        and_(models.DataIdentifierAssociation.scope == scope,
             models.DataIdentifierAssociation.name == name)
    )

    if source_rses:
        if len(source_rses) < 10:
            rse_clause = []
            for rse_id in source_rses:
                rse_clause.append(models.RSEFileAssociation.rse_id == rse_id)
            if rse_clause:
                stmt = select(
                    models.DataIdentifierAssociation.child_scope,
                    models.DataIdentifierAssociation.child_name,
                    models.RSEFileAssociation.rse_id
                ).with_hint(
                    models.DataIdentifierAssociation,
                    'INDEX_RS_ASC(CONTENTS CONTENTS_PK) NO_INDEX_FFS(CONTENTS CONTENTS_PK)',
                    'oracle'
                ).outerjoin(
                    models.RSEFileAssociation,
                    and_(models.DataIdentifierAssociation.child_scope == models.RSEFileAssociation.scope,
                         models.DataIdentifierAssociation.child_name == models.RSEFileAssociation.name,
                         models.RSEFileAssociation.state == ReplicaState.AVAILABLE,
                         or_(*rse_clause))
                ).where(
                    and_(models.DataIdentifierAssociation.scope == scope,
                         models.DataIdentifierAssociation.name == name)
                )
    if total_threads and total_threads > 1:
        stmt = filter_thread_work(session=session,
                                  query=stmt,
                                  total_threads=total_threads,
                                  thread_id=thread_id,
                                  hash_variable='child_name')

    replicas = {}

    for child_scope, child_name, rse_id in session.execute(stmt):

        if (child_scope, child_name) in replicas:
            if rse_id:
                replicas[(child_scope, child_name)].append(rse_id)
        else:
            replicas[(child_scope, child_name)] = []
            if rse_id:
                replicas[(child_scope, child_name)].append(rse_id)

    return replicas


@read_session
def get_replica_atime(replica, *, session: "Session"):
    """
    Get the accessed_at timestamp for a replica. Just for testing.
    :param replicas: List of dictionaries {scope, name, rse_id, path}
    :param session: Database session to use.

    :returns: A datetime timestamp with the last access time.
    """
    stmt = select(
        models.RSEFileAssociation.accessed_at
    ).with_hint(
        models.RSEFileAssociation,
        'INDEX(REPLICAS REPLICAS_PK)',
        'oracle'
    ).where(
        and_(models.RSEFileAssociation.scope == replica['scope'],
             models.RSEFileAssociation.name == replica['name'],
             models.RSEFileAssociation.rse_id == replica['rse_id'])
    )
    return session.execute(stmt).scalar_one()


@transactional_session
def touch_collection_replicas(collection_replicas, *, session: "Session"):
    """
    Update the accessed_at timestamp of the given collection replicas.

    :param collection_replicas: the list of collection replicas.
    :param session: The database session in use.

    :returns: True, if successful, False otherwise.
    """

    now = datetime.utcnow()
    for collection_replica in collection_replicas:
        try:
            stmt = update(
                models.CollectionReplica
            ).where(
                and_(models.CollectionReplica.scope == collection_replica['scope'],
                     models.CollectionReplica.name == collection_replica['name'],
                     models.CollectionReplica.rse_id == collection_replica['rse_id'])
            ).values({
                models.CollectionReplica.accessed_at: collection_replica.get('accessed_at') or now
            }).execution_options(
                synchronize_session=False
            )
            session.execute(stmt)
        except DatabaseError:
            return False

    return True


@stream_session
def list_dataset_replicas(scope, name, deep=False, *, session: "Session"):
    """
    :param scope: The scope of the dataset.
    :param name: The name of the dataset.
    :param deep: Lookup at the file level.
    :param session: Database session to use.

    :returns: A list of dictionaries containing the dataset replicas
              with associated metrics and timestamps
    """

    if not deep:
        stmt = select(
            models.CollectionReplica.scope,
            models.CollectionReplica.name,
            models.RSE.rse,
            models.CollectionReplica.rse_id,
            models.CollectionReplica.bytes,
            models.CollectionReplica.length,
            models.CollectionReplica.available_bytes,
            models.CollectionReplica.available_replicas_cnt.label("available_length"),
            models.CollectionReplica.state,
            models.CollectionReplica.created_at,
            models.CollectionReplica.updated_at,
            models.CollectionReplica.accessed_at
        ).where(
            and_(models.CollectionReplica.scope == scope,
                 models.CollectionReplica.name == name,
                 models.CollectionReplica.did_type == DIDType.DATASET,
                 models.CollectionReplica.rse_id == models.RSE.id,
                 models.RSE.deleted == false())
        )

        for row in session.execute(stmt).all():
            yield row._asdict()

    else:
        # Find maximum values
        stmt = select(
            func.sum(models.DataIdentifierAssociation.bytes).label("bytes"),
            func.count().label("length")
        ).select_from(
            models.DataIdentifierAssociation
        ).with_hint(
            models.DataIdentifierAssociation,
            'INDEX_RS_ASC(CONTENTS CONTENTS_PK) NO_INDEX_FFS(CONTENTS CONTENTS_PK)',
            'oracle'
        ).where(
            and_(models.DataIdentifierAssociation.scope == scope,
                 models.DataIdentifierAssociation.name == name)
        )

        bytes_, length = session.execute(stmt).one()
        bytes_ = bytes_ or 0

        # Find archives that contain files of the requested dataset
        sub_query_stmt = select(
            models.DataIdentifierAssociation.scope.label('dataset_scope'),
            models.DataIdentifierAssociation.name.label('dataset_name'),
            models.DataIdentifierAssociation.bytes.label('file_bytes'),
            models.ConstituentAssociation.child_scope.label('file_scope'),
            models.ConstituentAssociation.child_name.label('file_name'),
            models.RSEFileAssociation.scope.label('replica_scope'),
            models.RSEFileAssociation.name.label('replica_name'),
            models.RSE.rse,
            models.RSE.id.label('rse_id'),
            models.RSEFileAssociation.created_at,
            models.RSEFileAssociation.accessed_at,
            models.RSEFileAssociation.updated_at
        ).where(
            and_(models.DataIdentifierAssociation.scope == scope,
                 models.DataIdentifierAssociation.name == name,
                 models.ConstituentAssociation.child_scope == models.DataIdentifierAssociation.child_scope,
                 models.ConstituentAssociation.child_name == models.DataIdentifierAssociation.child_name,
                 models.ConstituentAssociation.scope == models.RSEFileAssociation.scope,
                 models.ConstituentAssociation.name == models.RSEFileAssociation.name,
                 models.RSEFileAssociation.rse_id == models.RSE.id,
                 models.RSEFileAssociation.state == ReplicaState.AVAILABLE,
                 models.RSE.deleted == false())
        ).subquery()

        # Count the metrics
        group_query_stmt = select(
            sub_query_stmt.c.dataset_scope,
            sub_query_stmt.c.dataset_name,
            sub_query_stmt.c.file_scope,
            sub_query_stmt.c.file_name,
            sub_query_stmt.c.rse_id,
            sub_query_stmt.c.rse,
            func.sum(sub_query_stmt.c.file_bytes).label('file_bytes'),
            func.min(sub_query_stmt.c.created_at).label('created_at'),
            func.max(sub_query_stmt.c.updated_at).label('updated_at'),
            func.max(sub_query_stmt.c.accessed_at).label('accessed_at')
        ).group_by(
            sub_query_stmt.c.dataset_scope,
            sub_query_stmt.c.dataset_name,
            sub_query_stmt.c.file_scope,
            sub_query_stmt.c.file_name,
            sub_query_stmt.c.rse_id,
            sub_query_stmt.c.rse
        ).subquery()

        # Bring it in the same column state as the non-archive query
        full_query_stmt = select(
            group_query_stmt.c.dataset_scope.label('scope'),
            group_query_stmt.c.dataset_name.label('name'),
            group_query_stmt.c.rse_id,
            group_query_stmt.c.rse,
            func.sum(group_query_stmt.c.file_bytes).label('available_bytes'),
            func.count().label('available_length'),
            func.min(group_query_stmt.c.created_at).label('created_at'),
            func.max(group_query_stmt.c.updated_at).label('updated_at'),
            func.max(group_query_stmt.c.accessed_at).label('accessed_at')
        ).group_by(
            group_query_stmt.c.dataset_scope,
            group_query_stmt.c.dataset_name,
            group_query_stmt.c.rse_id,
            group_query_stmt.c.rse
        )

        # Find the non-archive dataset replicas
        sub_query_stmt = select(
            models.DataIdentifierAssociation.scope,
            models.DataIdentifierAssociation.name,
            models.RSEFileAssociation.rse_id,
            func.sum(models.RSEFileAssociation.bytes).label("available_bytes"),
            func.count().label("available_length"),
            func.min(models.RSEFileAssociation.created_at).label("created_at"),
            func.max(models.RSEFileAssociation.updated_at).label("updated_at"),
            func.max(models.RSEFileAssociation.accessed_at).label("accessed_at")
        ).with_hint(
            models.DataIdentifierAssociation,
            'INDEX_RS_ASC(CONTENTS CONTENTS_PK) INDEX_RS_ASC(REPLICAS REPLICAS_PK) NO_INDEX_FFS(CONTENTS CONTENTS_PK)',
            'oracle'
        ).where(
            and_(models.DataIdentifierAssociation.child_scope == models.RSEFileAssociation.scope,
                 models.DataIdentifierAssociation.child_name == models.RSEFileAssociation.name,
                 models.DataIdentifierAssociation.scope == scope,
                 models.DataIdentifierAssociation.name == name,
                 models.RSEFileAssociation.state == ReplicaState.AVAILABLE)
        ).group_by(
            models.DataIdentifierAssociation.scope,
            models.DataIdentifierAssociation.name,
            models.RSEFileAssociation.rse_id
        ).subquery()

        stmt = select(
            sub_query_stmt.c.scope,
            sub_query_stmt.c.name,
            sub_query_stmt.c.rse_id,
            models.RSE.rse,
            sub_query_stmt.c.available_bytes,
            sub_query_stmt.c.available_length,
            sub_query_stmt.c.created_at,
            sub_query_stmt.c.updated_at,
            sub_query_stmt.c.accessed_at
        ).where(
            and_(sub_query_stmt.c.rse_id == models.RSE.id,
                 models.RSE.deleted == false())
        )

        # Join everything together
        final_stmt = stmt.union_all(full_query_stmt)
        for row in session.execute(final_stmt).all():
            replica = row._asdict()
            replica['length'], replica['bytes'] = length, bytes_
            if replica['length'] == row.available_length:
                replica['state'] = ReplicaState.AVAILABLE
            else:
                replica['state'] = ReplicaState.UNAVAILABLE
            yield replica


@stream_session
def list_dataset_replicas_bulk(names_by_intscope, *, session: "Session"):
    """
    :param names_by_intscope: The dictionary of internal scopes pointing at the list of names.
    :param session: Database session to use.

    :returns: A list of dictionaries containing the dataset replicas
              with associated metrics and timestamps
    """

    condition = []
    for scope in names_by_intscope:
        condition.append(and_(models.CollectionReplica.scope == scope,
                              models.CollectionReplica.name.in_(names_by_intscope[scope])))

    try:
        # chunk size refers to the number of different scopes, see above
        for chunk in chunks(condition, 10):
            stmt = select(
                models.CollectionReplica.scope,
                models.CollectionReplica.name,
                models.RSE.rse,
                models.CollectionReplica.rse_id,
                models.CollectionReplica.bytes,
                models.CollectionReplica.length,
                models.CollectionReplica.available_bytes,
                models.CollectionReplica.available_replicas_cnt.label("available_length"),
                models.CollectionReplica.state,
                models.CollectionReplica.created_at,
                models.CollectionReplica.updated_at,
                models.CollectionReplica.accessed_at
            ).where(
                and_(models.CollectionReplica.did_type == DIDType.DATASET,
                     models.CollectionReplica.rse_id == models.RSE.id,
                     models.RSE.deleted == false(),
                     or_(*chunk))
            )

            for row in session.execute(stmt).all():
                yield row._asdict()
    except NoResultFound:
        raise exception.DataIdentifierNotFound('No Data Identifiers found')


@stream_session
def list_dataset_replicas_vp(scope, name, deep=False, *, session: "Session", logger=logging.log):
    """
    List dataset replicas for a DID (scope:name) using the
    Virtual Placement service.

    NOTICE: This is an RnD function and might change or go away at any time.

    :param scope: The scope of the dataset.
    :param name: The name of the dataset.
    :param deep: Lookup at the file level.
    :param session: Database session to use.

    :returns: If VP exists and there is at least one non-TAPE replica, returns a list of dicts of sites
    """
    vp_endpoint = get_vp_endpoint()
    vp_replies = ['other']
    nr_replies = 5  # force limit reply size

    if not vp_endpoint:
        return vp_replies

    try:
        vp_replies = requests.get('{}/ds/{}/{}:{}'.format(vp_endpoint, nr_replies, scope, name),
                                  verify=False,
                                  timeout=1)
        if vp_replies.status_code == 200:
            vp_replies = vp_replies.json()
        else:
            vp_replies = ['other']
    except requests.exceptions.RequestException as re:
        logger(logging.ERROR, 'In list_dataset_replicas_vp, could not access {}. Error:{}'.format(vp_endpoint, re))
        vp_replies = ['other']

    if vp_replies != ['other']:
        # check that there is at least one regular replica
        # that is not on tape and has a protocol  with scheme "root"
        # and can be accessed from WAN
        accessible_replica_exists = False
        for reply in list_dataset_replicas(scope=scope, name=name, deep=deep, session=session):
            if reply['state'] != ReplicaState.AVAILABLE:
                continue
            rse_info = rsemgr.get_rse_info(rse=reply['rse'], vo=scope.vo, session=session)
            if rse_info['rse_type'] == 'TAPE':
                continue
            for prot in rse_info['protocols']:
                if prot['scheme'] == 'root' and prot['domains']['wan']['read']:
                    accessible_replica_exists = True
                    break
            if accessible_replica_exists is True:
                break
        if accessible_replica_exists is True:
            for vp_reply in vp_replies:
                yield {'vp': True, 'site': vp_reply}


@stream_session
def list_datasets_per_rse(rse_id, filters=None, limit=None, *, session: "Session"):
    """
    List datasets at a RSE.

    :param rse: the rse id.
    :param filters: dictionary of attributes by which the results should be filtered.
    :param limit: limit number.
    :param session: Database session to use.

    :returns: A list of dict dataset replicas
    """
    stmt = select(
        models.CollectionReplica.scope,
        models.CollectionReplica.name,
        models.RSE.id.label('rse_id'),
        models.RSE.rse,
        models.CollectionReplica.bytes,
        models.CollectionReplica.length,
        models.CollectionReplica.available_bytes,
        models.CollectionReplica.available_replicas_cnt.label("available_length"),
        models.CollectionReplica.state,
        models.CollectionReplica.created_at,
        models.CollectionReplica.updated_at,
        models.CollectionReplica.accessed_at
    ).where(
        and_(models.CollectionReplica.did_type == DIDType.DATASET,
             models.CollectionReplica.rse_id == models.RSE.id,
             models.RSE.deleted == false(),
             models.RSE.id == rse_id)
    )

    for (k, v) in filters and filters.items() or []:
        if k == 'name' or k == 'scope':
            v_str = v if k != 'scope' else v.internal
            if '*' in v_str or '%' in v_str:
                if session.bind.dialect.name == 'postgresql':  # PostgreSQL escapes automatically
                    stmt = stmt.where(getattr(models.CollectionReplica, k).like(v_str.replace('*', '%')))
                else:
                    stmt = stmt.where(getattr(models.CollectionReplica, k).like(v_str.replace('*', '%'), escape='\\'))
            else:
                stmt = stmt.where(getattr(models.CollectionReplica, k) == v)
                # hints ?
        elif k == 'created_before':
            created_before = str_to_date(v)
            stmt = stmt.where(models.CollectionReplica.created_at <= created_before)
        elif k == 'created_after':
            created_after = str_to_date(v)
            stmt = stmt.where(models.CollectionReplica.created_at >= created_after)
        else:
            stmt = stmt.where(getattr(models.CollectionReplica, k) == v)

    if limit:
        stmt = stmt.limit(limit)

    for row in session.execute(stmt).all():
        yield row._asdict()


@stream_session
def list_replicas_per_rse(
    rse_id: str,
    limit: "Optional[int]" = None,
    *,
    session: "Session"
) -> "Iterator[dict[str, Any]]":
    """List all replicas at a given RSE."""
    list_stmt = select(
        models.RSEFileAssociation
    ).where(
        models.RSEFileAssociation.rse_id == rse_id
    )

    if limit:
        list_stmt = list_stmt.limit(limit)

    for replica in session.execute(list_stmt).yield_per(100).scalars():
        yield replica.to_dict()


@transactional_session
def get_cleaned_updated_collection_replicas(total_workers, worker_number, limit=None, *, session: "Session"):
    """
    Get update request for collection replicas.
    :param total_workers:      Number of total workers.
    :param worker_number:      id of the executing worker.
    :param limit:              Maximum numberws to return.
    :param session:            Database session in use.
    :returns:                  List of update requests for collection replicas.
    """

    stmt = delete(
        models.UpdatedCollectionReplica
    ).where(
        and_(models.UpdatedCollectionReplica.rse_id.is_(None),
             ~exists().where(
                 and_(models.CollectionReplica.name == models.UpdatedCollectionReplica.name,
                      models.CollectionReplica.scope == models.UpdatedCollectionReplica.scope)))
    ).execution_options(
        synchronize_session=False
    )
    session.execute(stmt)

    # Delete update requests which do not have collection_replicas
    stmt = delete(
        models.UpdatedCollectionReplica
    ).where(
        and_(models.UpdatedCollectionReplica.rse_id.isnot(None),
             ~exists().where(
                 and_(models.CollectionReplica.name == models.UpdatedCollectionReplica.name,
                      models.CollectionReplica.scope == models.UpdatedCollectionReplica.scope,
                      models.CollectionReplica.rse_id == models.UpdatedCollectionReplica.rse_id)))
    ).execution_options(
        synchronize_session=False
    )
    session.execute(stmt)

    # Delete duplicates
    if session.bind.dialect.name == 'oracle':
        schema = ''
        if BASE.metadata.schema:
            schema = BASE.metadata.schema + '.'
        session.execute(text('DELETE FROM {schema}updated_col_rep A WHERE A.rowid > ANY (SELECT B.rowid FROM {schema}updated_col_rep B WHERE A.scope = B.scope AND A.name=B.name AND A.did_type=B.did_type AND (A.rse_id=B.rse_id OR (A.rse_id IS NULL and B.rse_id IS NULL)))'.format(schema=schema)))  # NOQA: E501
    elif session.bind.dialect.name == 'mysql':
        subquery1 = select(
            func.max(models.UpdatedCollectionReplica.id).label('max_id')
        ).group_by(
            models.UpdatedCollectionReplica.scope,
            models.UpdatedCollectionReplica.name,
            models.UpdatedCollectionReplica.rse_id
        ).subquery()

        subquery2 = select(
            subquery1.c.max_id
        )

        stmt_del = delete(
            models.UpdatedCollectionReplica
        ).where(
            models.UpdatedCollectionReplica.id.not_in(subquery2)
        ).execution_options(
            synchronize_session=False
        )
        session.execute(stmt_del)
    else:
        stmt = select(models.UpdatedCollectionReplica)
        update_requests_with_rse_id = []
        update_requests_without_rse_id = []
        duplicate_request_ids = []
        for update_request in session.execute(stmt).scalars().all():
            if update_request.rse_id is not None:
                small_request = {'name': update_request.name, 'scope': update_request.scope, 'rse_id': update_request.rse_id}
                if small_request not in update_requests_with_rse_id:
                    update_requests_with_rse_id.append(small_request)
                else:
                    duplicate_request_ids.append(update_request.id)
                    continue
            else:
                small_request = {'name': update_request.name, 'scope': update_request.scope}
                if small_request not in update_requests_without_rse_id:
                    update_requests_without_rse_id.append(small_request)
                else:
                    duplicate_request_ids.append(update_request.id)
                    continue
        for chunk in chunks(duplicate_request_ids, 100):
            stmt = delete(
                models.UpdatedCollectionReplica
            ).where(
                models.UpdatedCollectionReplica.id.in_(chunk)
            ).execution_options(
                synchronize_session=False
            )
            session.execute(stmt)

    stmt = select(models.UpdatedCollectionReplica)
    if limit:
        stmt = stmt.limit(limit)
    return [update_request.to_dict() for update_request in session.execute(stmt).scalars().all()]


@transactional_session
def update_collection_replica(update_request, *, session: "Session"):
    """
    Update a collection replica.
    :param update_request: update request from the upated_col_rep table.
    """
    if update_request['rse_id'] is not None:
        # Check one specific dataset replica
        ds_length = 0
        old_available_replicas = 0
        ds_bytes = 0
        ds_replica_state = None
        ds_available_bytes = 0
        available_replicas = 0

        try:
            stmt = select(
                models.CollectionReplica
            ).where(
                and_(models.CollectionReplica.scope == update_request['scope'],
                     models.CollectionReplica.name == update_request['name'],
                     models.CollectionReplica.rse_id == update_request['rse_id'])
            )
            collection_replica = session.execute(stmt).scalar_one()
            ds_length = collection_replica.length
            old_available_replicas = collection_replica.available_replicas_cnt
            ds_bytes = collection_replica.bytes
        except NoResultFound:
            pass

        try:
            stmt = select(
                func.sum(models.RSEFileAssociation.bytes).label('ds_available_bytes'),
                func.count().label('available_replicas')
            ).select_from(
                models.RSEFileAssociation
            ).where(
                and_(models.RSEFileAssociation.scope == models.DataIdentifierAssociation.child_scope,
                     models.RSEFileAssociation.name == models.DataIdentifierAssociation.child_name,
                     models.RSEFileAssociation.rse_id == update_request['rse_id'],
                     models.RSEFileAssociation.state == ReplicaState.AVAILABLE,
                     models.DataIdentifierAssociation.name == update_request['name'],
                     models.DataIdentifierAssociation.scope == update_request['scope'])
            )
            file_replica = session.execute(stmt).one()

            available_replicas = file_replica.available_replicas
            ds_available_bytes = file_replica.ds_available_bytes
        except NoResultFound:
            pass

        if available_replicas >= ds_length:
            ds_replica_state = ReplicaState.AVAILABLE
        else:
            ds_replica_state = ReplicaState.UNAVAILABLE

        if old_available_replicas is not None and old_available_replicas > 0 and available_replicas == 0:
            stmt = delete(
                models.CollectionReplica
            ).where(
                and_(models.CollectionReplica.scope == update_request['scope'],
                     models.CollectionReplica.name == update_request['name'],
                     models.CollectionReplica.rse_id == update_request['rse_id'])
            )
            session.execute(stmt)
        else:
            stmt = select(
                models.CollectionReplica
            ).where(
                and_(models.CollectionReplica.scope == update_request['scope'],
                     models.CollectionReplica.name == update_request['name'],
                     models.CollectionReplica.rse_id == update_request['rse_id'])
            )
            updated_replica = session.execute(stmt).scalar_one()

            updated_replica.state = ds_replica_state
            updated_replica.available_replicas_cnt = available_replicas
            updated_replica.length = ds_length
            updated_replica.bytes = ds_bytes
            updated_replica.available_bytes = ds_available_bytes
    else:
        stmt = select(
            func.count().label('ds_length'),
            func.sum(models.DataIdentifierAssociation.bytes).label('ds_bytes')
        ).select_from(
            models.DataIdentifierAssociation
        ).where(
            and_(models.DataIdentifierAssociation.scope == update_request['scope'],
                 models.DataIdentifierAssociation.name == update_request['name'])
        )
        association = session.execute(stmt).one()

        # Check all dataset replicas
        ds_length = association.ds_length
        ds_bytes = association.ds_bytes
        ds_replica_state = None

        stmt = select(
            models.CollectionReplica
        ).where(
            and_(models.CollectionReplica.scope == update_request['scope'],
                 models.CollectionReplica.name == update_request['name'])
        )
        for collection_replica in session.execute(stmt).scalars().all():
            if ds_length:
                collection_replica.length = ds_length
            else:
                collection_replica.length = 0
            if ds_bytes:
                collection_replica.bytes = ds_bytes
            else:
                collection_replica.bytes = 0

        stmt = select(
            func.sum(models.RSEFileAssociation.bytes).label('ds_available_bytes'),
            func.count().label('available_replicas'),
            models.RSEFileAssociation.rse_id
        ).select_from(
            models.RSEFileAssociation
        ).where(
            and_(models.RSEFileAssociation.scope == models.DataIdentifierAssociation.child_scope,
                 models.RSEFileAssociation.name == models.DataIdentifierAssociation.child_name,
                 models.RSEFileAssociation.state == ReplicaState.AVAILABLE,
                 models.DataIdentifierAssociation.name == update_request['name'],
                 models.DataIdentifierAssociation.scope == update_request['scope'])
        ).group_by(
            models.RSEFileAssociation.rse_id
        )

        for file_replica in session.execute(stmt).all():
            if file_replica.available_replicas >= ds_length:
                ds_replica_state = ReplicaState.AVAILABLE
            else:
                ds_replica_state = ReplicaState.UNAVAILABLE

            stmt = select(
                models.CollectionReplica
            ).where(
                and_(models.CollectionReplica.scope == update_request['scope'],
                     models.CollectionReplica.name == update_request['name'],
                     models.CollectionReplica.rse_id == file_replica.rse_id)
            )
            collection_replica = session.execute(stmt).scalars().first()
            if collection_replica:
                collection_replica.state = ds_replica_state
                collection_replica.available_replicas_cnt = file_replica.available_replicas
                collection_replica.available_bytes = file_replica.ds_available_bytes

    stmt = delete(
        models.UpdatedCollectionReplica
    ).where(
        models.UpdatedCollectionReplica.id == update_request['id']
    )
    session.execute(stmt)


@read_session
def get_bad_pfns(limit=10000, thread=None, total_threads=None, *, session: "Session"):
    """
    Returns a list of bad PFNs

    :param limit: The maximum number of replicas returned.
    :param thread: The assigned thread for this minos instance.
    :param total_threads: The total number of minos threads.
    :param session: The database session in use.

    returns: list of PFNs {'pfn': pfn, 'state': state, 'reason': reason, 'account': account, 'expires_at': expires_at}
    """
    result = []

    stmt = select(
        models.BadPFN.path,
        models.BadPFN.state,
        models.BadPFN.reason,
        models.BadPFN.account,
        models.BadPFN.expires_at
    )
    stmt = filter_thread_work(session=session, query=stmt, total_threads=total_threads, thread_id=thread, hash_variable='path')
    stmt = stmt.order_by(
        models.BadPFN.created_at
    ).limit(
        limit
    )

    for path, state, reason, account, expires_at in session.execute(stmt).yield_per(1000):
        result.append({'pfn': clean_pfns([str(path)])[0], 'state': state, 'reason': reason, 'account': account, 'expires_at': expires_at})
    return result


@transactional_session
def bulk_add_bad_replicas(replicas, account, state=BadFilesStatus.TEMPORARY_UNAVAILABLE, reason=None, expires_at=None, *, session: "Session"):
    """
    Bulk add new bad replicas.

    :param replicas: the list of bad replicas.
    :param account: The account who declared the bad replicas.
    :param state: The state of the file (SUSPICIOUS, BAD or TEMPORARY_UNAVAILABLE).
    :param session: The database session in use.

    :returns: True is successful.
    """
    for replica in replicas:
        scope_name_rse_state = and_(models.BadReplica.scope == replica['scope'],
                                    models.BadReplica.name == replica['name'],
                                    models.BadReplica.rse_id == replica['rse_id'],
                                    models.BadReplica.state == state)
        insert_new_row = True
        if state == BadFilesStatus.TEMPORARY_UNAVAILABLE:
            stmt = select(
                models.BadReplica
            ).where(
                scope_name_rse_state
            )
            if session.execute(stmt).scalar_one_or_none():
                stmt = update(
                    models.BadReplica
                ).where(
                    scope_name_rse_state
                ).values({
                    models.BadReplica.state: BadFilesStatus.TEMPORARY_UNAVAILABLE,
                    models.BadReplica.updated_at: datetime.utcnow(),
                    models.BadReplica.account: account,
                    models.BadReplica.reason: reason,
                    models.BadReplica.expires_at: expires_at
                }).execution_options(
                    synchronize_session=False
                )
                session.execute(stmt)

                insert_new_row = False
        if insert_new_row:
            new_bad_replica = models.BadReplica(scope=replica['scope'], name=replica['name'], rse_id=replica['rse_id'], reason=reason,
                                                state=state, account=account, bytes=None, expires_at=expires_at)
            new_bad_replica.save(session=session, flush=False)
    try:
        session.flush()
    except IntegrityError as error:
        raise exception.RucioException(error.args)
    except DatabaseError as error:
        raise exception.RucioException(error.args)
    except FlushError as error:
        if match('New instance .* with identity key .* conflicts with persistent instance', error.args[0]):
            raise exception.DataIdentifierAlreadyExists('Data Identifier already exists!')
        raise exception.RucioException(error.args)
    return True


@transactional_session
def bulk_delete_bad_pfns(pfns, *, session: "Session"):
    """
    Bulk delete bad PFNs.

    :param pfns: the list of new files.
    :param session: The database session in use.

    :returns: True is successful.
    """
    pfn_clause = []
    for pfn in pfns:
        pfn_clause.append(models.BadPFN.path == pfn)

    for chunk in chunks(pfn_clause, 100):
        stmt = delete(
            models.BadPFN
        ).where(
            or_(*chunk)
        ).execution_options(
            synchronize_session=False
        )
        session.execute(stmt)

    return True


@transactional_session
def bulk_delete_bad_replicas(bad_replicas, *, session: "Session"):
    """
    Bulk delete bad replica.

    :param bad_replicas:    The list of bad replicas to delete (Dictionaries).
    :param session:         The database session in use.

    :returns: True is successful.
    """
    replica_clause = []
    for replica in bad_replicas:
        replica_clause.append(and_(models.BadReplica.scope == replica['scope'],
                                   models.BadReplica.name == replica['name'],
                                   models.BadReplica.rse_id == replica['rse_id'],
                                   models.BadReplica.state == replica['state']))

    for chunk in chunks(replica_clause, 100):
        stmt = delete(
            models.BadReplica
        ).where(
            or_(*chunk)
        ).execution_options(
            synchronize_session=False
        )
        session.execute(stmt)
    return True


@transactional_session
def add_bad_pfns(pfns, account, state, reason=None, expires_at=None, *, session: "Session"):
    """
    Add bad PFNs.

    :param pfns: the list of new files.
    :param account: The account who declared the bad replicas.
    :param state: One of the possible states : BAD, SUSPICIOUS, TEMPORARY_UNAVAILABLE.
    :param reason: A string describing the reason of the loss.
    :param expires_at: Specify a timeout for the TEMPORARY_UNAVAILABLE replicas. None for BAD files.
    :param session: The database session in use.

    :returns: True is successful.
    """

    if isinstance(state, str):
        rep_state = BadPFNStatus[state]
    else:
        rep_state = state

    if rep_state == BadPFNStatus.TEMPORARY_UNAVAILABLE and expires_at is None:
        raise exception.InputValidationError("When adding a TEMPORARY UNAVAILABLE pfn the expires_at value should be set.")
    elif rep_state == BadPFNStatus.BAD and expires_at is not None:
        raise exception.InputValidationError("When adding a BAD pfn the expires_at value shouldn't be set.")

    pfns = clean_pfns(pfns)
    for pfn in pfns:
        new_pfn = models.BadPFN(path=str(pfn), account=account, state=rep_state, reason=reason, expires_at=expires_at)
        new_pfn = session.merge(new_pfn)
        new_pfn.save(session=session, flush=False)

    try:
        session.flush()
    except IntegrityError as error:
        raise exception.RucioException(error.args)
    except DatabaseError as error:
        raise exception.RucioException(error.args)
    except FlushError as error:
        if match('New instance .* with identity key .* conflicts with persistent instance', error.args[0]):
            raise exception.Duplicate('One PFN already exists!')
        raise exception.RucioException(error.args)
    return True


@read_session
def list_expired_temporary_unavailable_replicas(total_workers, worker_number, limit=10000, *, session: "Session"):
    """
    List the expired temporary unavailable replicas

    :param total_workers:   Number of total workers.
    :param worker_number:   id of the executing worker.
    :param limit:           The maximum number of replicas returned.
    :param session:         The database session in use.
    """

    stmt = select(
        models.BadReplica.scope,
        models.BadReplica.name,
        models.BadReplica.rse_id,
    ).with_hint(
        models.ReplicationRule,
        'INDEX(bad_replicas BAD_REPLICAS_EXPIRES_AT_IDX)',
        'oracle'
    ).where(
        and_(models.BadReplica.state == BadFilesStatus.TEMPORARY_UNAVAILABLE,
             models.BadReplica.expires_at < datetime.utcnow())
    ).order_by(
        models.BadReplica.expires_at
    )

    stmt = filter_thread_work(session=session, query=stmt, total_threads=total_workers, thread_id=worker_number, hash_variable='name')
    stmt = stmt.limit(limit)

    return session.execute(stmt).all()


@read_session
def get_replicas_state(scope=None, name=None, *, session: "Session"):
    """
    Method used by the necromancer to get all the replicas of a DIDs
    :param scope: The scope of the file.
    :param name: The name of the file.
    :param session: The database session in use.

    :returns: A dictionary with the list of states as keys and the rse_ids as value
    """

    stmt = select(
        models.RSEFileAssociation.rse_id,
        models.RSEFileAssociation.state
    ).where(
        and_(models.RSEFileAssociation.scope == scope,
             models.RSEFileAssociation.name == name)
    )
    states = {}
    for res in session.execute(stmt).all():
        rse_id, state = res
        if state not in states:
            states[state] = []
        states[state].append(rse_id)
    return states


@read_session
def get_suspicious_files(
    rse_expression: str,
    available_elsewhere: int,
    filter_: "Optional[dict[str, Any]]" = None,
    logger: "LoggerFunction" = logging.log,
    younger_than: "Optional[datetime]" = None,
    nattempts: int = 0,
    nattempts_exact: bool = False,
    *,
    session: "Session",
    exclude_states: "Optional[Iterable[str]]" = None,
    is_suspicious: bool = False
) -> "list[dict[str, Any]]":
    """
    Gets a list of replicas from bad_replicas table which are: declared more than <nattempts> times since <younger_than> date,
    present on the RSE specified by the <rse_expression> and do not have a state in <exclude_states> list.
    Selected replicas can also be required to be <available_elsewhere> on another RSE than the one declared in bad_replicas table and/or
    be declared as <is_suspicious> in the bad_replicas table.
    Keyword Arguments:
    :param younger_than: Datetime object to select the replicas which were declared since younger_than date. Default value = 10 days ago.
    :param nattempts: The minimum number of replica appearances in the bad_replica DB table from younger_than date. Default value = 0.
    :param nattempts_exact: If True, then only replicas with exactly 'nattempts' appearances in the bad_replica DB table are retrieved. Replicas with more appearances are ignored.
    :param rse_expression: The RSE expression where the replicas are located.
    :param filter_: Dictionary of attributes by which the RSE results should be filtered. e.g.: {'availability_write': True}
    :param exclude_states: List of states which eliminates replicas from search result if any of the states in the list
                            was declared for a replica since younger_than date. Allowed values
                            = ['B', 'R', 'D', 'L', 'T', 'S'] (meaning 'BAD', 'RECOVERED', 'DELETED', 'LOST', 'TEMPORARY_UNAVAILABLE', 'SUSPICIOUS').
    :param available_elsewhere: Default: SuspiciousAvailability["ALL"].value, all suspicious replicas are returned.
                                 If SuspiciousAvailability["EXIST_COPIES"].value, only replicas that additionally have copies declared as AVAILABLE on at least one other RSE
                                 than the one in the bad_replicas table will be taken into account.
                                 If SuspiciousAvailability["LAST_COPY"].value, only replicas that do not have another copy declared as AVAILABLE on another RSE will be taken into account.
    :param is_suspicious: If True, only replicas declared as SUSPICIOUS in bad replicas table will be taken into account. Default value = False.
    :param session: The database session in use. Default value = None.

    :returns: a list of replicas:
    [{'scope': scope, 'name': name, 'rse': rse, 'rse_id': rse_id, cnt': cnt, 'created_at': created_at}, ...]
    """

    exclude_states = exclude_states or ['B', 'R', 'D']
    if available_elsewhere not in [SuspiciousAvailability["ALL"].value, SuspiciousAvailability["EXIST_COPIES"].value, SuspiciousAvailability["LAST_COPY"].value]:
        logger(logging.WARNING, """ERROR, available_elsewhere must be set to one of the following:
        SuspiciousAvailability["ALL"].value: (default) all suspicious replicas are returned
        SuspiciousAvailability["EXIST_COPIES"].value: only replicas that additionally have copies declared as AVAILABLE on at least one other RSE are returned
        SuspiciousAvailability["LAST_COPY"].value: only replicas that do not have another copy declared as AVAILABLE on another RSE are returned""")
        raise exception.RucioException("""ERROR, available_elsewhere must be set to one of the following:
        SuspiciousAvailability["ALL"].value: (default) all suspicious replicas are returned
        SuspiciousAvailability["EXIST_COPIES"].value: only replicas that additionally have copies declared as AVAILABLE on at least one other RSE are returned
        SuspiciousAvailability["LAST_COPY"].value: only replicas that do not have another copy declared as AVAILABLE on another RSE are returned""")

    # only for the 2 web api used parameters, checking value types and assigning the default values
    if not isinstance(nattempts, int):
        nattempts = 0
    if not isinstance(younger_than, datetime):
        younger_than = datetime.utcnow() - timedelta(days=10)

    # assembling exclude_states_clause
    exclude_states_clause = []
    for state in exclude_states:
        exclude_states_clause.append(BadFilesStatus(state))

    # making aliases for bad_replicas and replicas tables
    bad_replicas_alias = aliased(models.BadReplica, name='bad_replicas_alias')
    replicas_alias = aliased(models.RSEFileAssociation, name='replicas_alias')

    # assembling the selection rse_clause
    rse_clause = []
    if rse_expression:
        parsedexp = parse_expression(expression=rse_expression, filter_=filter_, session=session)
        for rse in parsedexp:
            rse_clause.append(models.RSEFileAssociation.rse_id == rse['id'])

    stmt = select(
        func.count(),
        bad_replicas_alias.scope,
        bad_replicas_alias.name,
        models.RSEFileAssociation.rse_id,
        func.min(models.RSEFileAssociation.created_at)
    ).select_from(
        bad_replicas_alias
    ).where(
        models.RSEFileAssociation.rse_id == bad_replicas_alias.rse_id,
        models.RSEFileAssociation.scope == bad_replicas_alias.scope,
        models.RSEFileAssociation.name == bad_replicas_alias.name,
        bad_replicas_alias.created_at >= younger_than
    )
    if is_suspicious:
        stmt = stmt.where(bad_replicas_alias.state == BadFilesStatus.SUSPICIOUS)
    if rse_clause:
        stmt = stmt.where(or_(*rse_clause))

    # Only return replicas that have at least one copy on another RSE
    if available_elsewhere == SuspiciousAvailability["EXIST_COPIES"].value:
        available_replica = exists(select(1)
                                   .where(and_(replicas_alias.state == ReplicaState.AVAILABLE,
                                               replicas_alias.scope == bad_replicas_alias.scope,
                                               replicas_alias.name == bad_replicas_alias.name,
                                               replicas_alias.rse_id != bad_replicas_alias.rse_id)))
        stmt = stmt.where(available_replica)

    # Only return replicas that are the last remaining copy
    if available_elsewhere == SuspiciousAvailability["LAST_COPY"].value:
        last_replica = ~exists(select(1)
                               .where(and_(replicas_alias.state == ReplicaState.AVAILABLE,
                                           replicas_alias.scope == bad_replicas_alias.scope,
                                           replicas_alias.name == bad_replicas_alias.name,
                                           replicas_alias.rse_id != bad_replicas_alias.rse_id)))
        stmt = stmt.where(last_replica)

    # it is required that the selected replicas
    # do not occur as BAD/DELETED/LOST/RECOVERED/...
    # in the bad_replicas table during the same time window.
    other_states_present = exists(select(1)
                                  .where(and_(models.BadReplica.scope == bad_replicas_alias.scope,
                                              models.BadReplica.name == bad_replicas_alias.name,
                                              models.BadReplica.created_at >= younger_than,
                                              models.BadReplica.rse_id == bad_replicas_alias.rse_id,
                                              models.BadReplica.state.in_(exclude_states_clause))))
    stmt = stmt.where(not_(other_states_present))

    # finally, the results are grouped by RSE, scope, name and required to have
    # at least 'nattempts' occurrences in the result of the query per replica.
    # If nattempts_exact, then only replicas are required to have exactly
    # 'nattempts' occurrences.
    if nattempts_exact:
        stmt = stmt.group_by(
            models.RSEFileAssociation.rse_id,
            bad_replicas_alias.scope,
            bad_replicas_alias.name
        ).having(
            func.count() == nattempts
        )
        query_result = session.execute(stmt).all()
    else:
        stmt = stmt.group_by(
            models.RSEFileAssociation.rse_id,
            bad_replicas_alias.scope,
            bad_replicas_alias.name
        ).having(
            func.count() > nattempts
        )
        query_result = session.execute(stmt).all()

    # translating the rse_id to RSE name and assembling the return list of dictionaries
    result = []
    rses = {}
    for cnt, scope, name, rse_id, created_at in query_result:
        if rse_id not in rses:
            rse = get_rse_name(rse_id=rse_id, session=session)
            rses[rse_id] = rse
        result.append({'scope': scope, 'name': name, 'rse': rses[rse_id], 'rse_id': rse_id, 'cnt': cnt, 'created_at': created_at})

    return result


@read_session
def get_suspicious_reason(rse_id, scope, name, nattempts=0, logger=logging.log, *, session: "Session"):
    """
    Returns the error message(s) which lead to the replica(s) being declared suspicious.

    :param rse_id: ID of RSE.
    :param scope: Scope of the replica DID.
    :param name: Name of the replica DID.
    :param session: The database session in use. Default value = None.
    """
    # Alias for bad replicas
    bad_replicas_alias = aliased(models.BadReplica, name='bad_replicas_alias')

    stmt = select(
        bad_replicas_alias.scope,
        bad_replicas_alias.name,
        bad_replicas_alias.reason,
        bad_replicas_alias.rse_id
    ).where(
        and_(bad_replicas_alias.rse_id == rse_id,
             bad_replicas_alias.scope == scope,
             bad_replicas_alias.state == 'S',
             bad_replicas_alias.name == name,
             ~exists(select(1).where(
                 and_(bad_replicas_alias.rse_id == rse_id,
                      bad_replicas_alias.name == name,
                      bad_replicas_alias.scope == scope,
                      bad_replicas_alias.state != 'S'))))
    )

    count_query = select(
        func.count()
    ).select_from(
        stmt.subquery()
    )
    count = session.execute(count_query).scalar_one()

    grouped_stmt = stmt.group_by(
        bad_replicas_alias.rse_id,
        bad_replicas_alias.scope,
        bad_replicas_alias.name,
        bad_replicas_alias.reason
    ).having(
        func.count() > nattempts
    )

    result = []
    rses = {}
    for scope_, name_, reason, rse_id_ in session.execute(grouped_stmt).all():
        if rse_id_ not in rses:
            rse = get_rse_name(rse_id=rse_id_, session=session)
            rses[rse_id_] = rse
        result.append({'scope': scope, 'name': name, 'rse': rses[rse_id_], 'rse_id': rse_id_, 'reason': reason, 'count': count})

    if len(result) > 1:
        logger(logging.WARNING, "Multiple reasons have been found. Please investigate.")

    return result


@transactional_session
def set_tombstone(rse_id, scope, name, tombstone=OBSOLETE, *, session: "Session"):
    """
    Sets a tombstone on a replica.

    :param rse_id: ID of RSE.
    :param scope: scope of the replica DID.
    :param name: name of the replica DID.
    :param tombstone: the tombstone to set. Default is OBSOLETE
    :param session: database session in use.
    """
    stmt = update(models.RSEFileAssociation).where(
        and_(models.RSEFileAssociation.rse_id == rse_id,
             models.RSEFileAssociation.name == name,
             models.RSEFileAssociation.scope == scope,
             ~exists().where(
                 and_(models.ReplicaLock.rse_id == rse_id,
                      models.ReplicaLock.name == name,
                      models.ReplicaLock.scope == scope)))
    ).prefix_with(
        '/*+ INDEX(REPLICAS REPLICAS_PK) */', dialect='oracle'
    ).values({
        models.RSEFileAssociation.tombstone: tombstone
    }).execution_options(
        synchronize_session=False
    )

    if session.execute(stmt).rowcount == 0:
        try:
            stmt = select(
                models.RSEFileAssociation.tombstone
            ).where(
                and_(models.RSEFileAssociation.rse_id == rse_id,
                     models.RSEFileAssociation.name == name,
                     models.RSEFileAssociation.scope == scope)
            )
            session.execute(stmt).scalar_one()
            raise exception.ReplicaIsLocked('Replica %s:%s on RSE %s is locked.' % (scope, name, get_rse_name(rse_id=rse_id, session=session)))
        except NoResultFound:
            raise exception.ReplicaNotFound('Replica %s:%s on RSE %s could not be found.' % (scope, name, get_rse_name(rse_id=rse_id, session=session)))


@read_session
def get_RSEcoverage_of_dataset(scope, name, *, session: "Session"):
    """
    Get total bytes present on RSEs

    :param scope:             Scope of the dataset
    :param name:              Name of the dataset
    :param session:           The db session.
    :return:                  Dictionary { rse_id : <total bytes present at rse_id> }
    """

    stmt = select(
        models.RSEFileAssociation.rse_id,
        func.sum(models.DataIdentifierAssociation.bytes)
    ).where(
        and_(models.DataIdentifierAssociation.child_scope == models.RSEFileAssociation.scope,
             models.DataIdentifierAssociation.child_name == models.RSEFileAssociation.name,
             models.DataIdentifierAssociation.scope == scope,
             models.DataIdentifierAssociation.name == name,
             models.RSEFileAssociation.state != ReplicaState.BEING_DELETED)
    ).group_by(
        models.RSEFileAssociation.rse_id
    )

    result = {}
    for rse_id, total in session.execute(stmt):
        if total:
            result[rse_id] = total

    return result

@transactional_session
def refresh_replicas(
        rse_id: Optional[str] = None, 
        replicas: Optional[Iterable[dict[str, Any]]] = None,
        *, 
        session: "Session"
) -> bool:
    """
    Updates the updated_at timestamp of the given replicas but don't wait if row is locked.

    :param rse_id: the RSE containing the replicas to refresh.
    :param replicas: a list with replicas (dictionary with the information of the affected replica).
    :param session: The database session in use.

    :returns: True, if successful, False otherwise.
    """

    if not replicas or not rse_id:
            return True
    
    tt_mngr = temp_table_mngr(session=session)
    scope_name_temp_table = tt_mngr.create_scope_name_table()

    values = [{'scope': replica['scope'].external, 'name': replica['name']} for replica in replicas]

    try:
        stmt = insert(
            scope_name_temp_table
        )
        session.execute(stmt, values)

        stmt = select(
            func.count(),
        ).join_from(
            scope_name_temp_table,
            models.RSEFileAssociation,
            and_(models.RSEFileAssociation.scope == scope_name_temp_table.scope,
                models.RSEFileAssociation.name == scope_name_temp_table.name,
                models.RSEFileAssociation.rse_id == rse_id,
                models.RSEFileAssociation.state == ReplicaState.BEING_DELETED)
        )

        total_to_refresh = session.execute(stmt).one()
        if total_to_refresh == 0:
            # nothing to do
            return True

        stmt = update(
            models.RSEFileAssociation
        ).prefix_with(
                '/*+ INDEX(REPLICAS REPLICAS_PK) */', dialect='oracle'
        ).where(
            exists(select(1)
                    .where(
                        and_(models.RSEFileAssociation.scope == scope_name_temp_table.scope,
                            models.RSEFileAssociation.name == scope_name_temp_table.name,
                            models.RSEFileAssociation.rse_id == rse_id)))
        ).where(
            models.RSEFileAssociation.state == ReplicaState.BEING_DELETED,
        ).values({
            models.RSEFileAssociation.updated_at: datetime.utcnow()
        }).execute_options(
            synchronize_session=False
        )

        session.execute(stmt)

        # clean up temporary table
        stmt = delete(scope_name_temp_table)
        session.execute(stmt)

    except DatabaseError:
        return False

    return True