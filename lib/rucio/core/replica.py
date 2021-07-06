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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2013-2018
# - Cedric Serfon <cedric.serfon@cern.ch>, 2013-2020
# - Ralph Vigne <ralph.vigne@cern.ch>, 2013-2014
# - Martin Barisits <martin.barisits@cern.ch>, 2013-2021
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014-2021
# - David Cameron <david.cameron@cern.ch>, 2014
# - Thomas Beermann <thomas.beermann@cern.ch>, 2014-2021
# - Wen Guan <wen.guan@cern.ch>, 2014-2015
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Dimitrios Christidis <dimitrios.christidis@cern.ch>, 2019-2021
# - Robert Illingworth <illingwo@fnal.gov>, 2019
# - James Perry <j.perry@epcc.ed.ac.uk>, 2019
# - Jaroslav Guenther <jaroslav.guenther@cern.ch>, 2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Ilija Vukotic <ivukotic@cern.ch>, 2020-2021
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Tomas Javurek <tomas.javurek@cern.ch>, 2020
# - Luc Goossens <luc.goossens@cern.ch>, 2020
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Eric Vaandering <ewv@fnal.gov>, 2020-2021
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Radu Carpa <radu.carpa@cern.ch>, 2021
# - Gabriele Fronzé <sucre.91@hotmail.it>, 2021

from __future__ import print_function

import heapq
import logging
import random
from collections import defaultdict
from copy import deepcopy
from curses.ascii import isprint
from datetime import datetime, timedelta
from hashlib import sha256
from json import dumps
from re import match
from struct import unpack
from traceback import format_exc

import requests
from dogpile.cache import make_region
from dogpile.cache.api import NO_VALUE
from six import string_types
from sqlalchemy import func, and_, or_, exists, not_
from sqlalchemy.exc import DatabaseError, IntegrityError
from sqlalchemy.orm import aliased
from sqlalchemy.orm.exc import FlushError, NoResultFound
from sqlalchemy.sql import label
from sqlalchemy.sql.expression import case, select, text, false, true

import rucio.core.did
import rucio.core.lock
from rucio.common import exception
from rucio.common.types import InternalScope
from rucio.common.utils import chunks, clean_surls, str_to_date, add_url_query
from rucio.core.config import get as config_get
from rucio.core.credential import get_signed_url
from rucio.core.rse import get_rse, get_rse_name, get_rse_attribute, get_rse_vo, list_rses
from rucio.core.rse_counter import decrease, increase
from rucio.core.rse_expression_parser import parse_expression
from rucio.db.sqla import models, filter_thread_work
from rucio.db.sqla.constants import (DIDType, ReplicaState, OBSOLETE, DIDAvailability,
                                     BadFilesStatus, RuleState, BadPFNStatus)
from rucio.db.sqla.session import (read_session, stream_session, transactional_session,
                                   DEFAULT_SCHEMA_NAME, BASE)
from rucio.rse import rsemanager as rsemgr

REGION = make_region().configure('dogpile.cache.memory', expiration_time=60)


@read_session
def get_bad_replicas_summary(rse_expression=None, from_date=None, to_date=None, filter=None, session=None):
    """
    List the bad file replicas summary. Method used by the rucio-ui.
    :param rse_expression: The RSE expression.
    :param from_date: The start date.
    :param to_date: The end date.
    :param filter: Dictionary of attributes by which the RSE results should be filtered. e.g.: {'availability_write': True}
    :param session: The database session in use.
    """
    result = []
    incidents = {}
    rse_clause = []
    if rse_expression:
        for rse in parse_expression(expression=rse_expression, filter=filter, session=session):
            rse_clause.append(models.BadReplicas.rse_id == rse['id'])
    elif filter:
        # Ensure we limit results to current VO even if we don't specify an RSE expression
        for rse in list_rses(filters=filter, session=session):
            rse_clause.append(models.BadReplicas.rse_id == rse['id'])

    if session.bind.dialect.name == 'oracle':
        to_days = func.trunc(models.BadReplicas.created_at, str('DD'))
    elif session.bind.dialect.name == 'mysql':
        to_days = func.date(models.BadReplicas.created_at)
    elif session.bind.dialect.name == 'postgresql':
        to_days = func.date_trunc('day', models.BadReplicas.created_at)
    else:
        to_days = func.strftime(models.BadReplicas.created_at, '%Y-%m-%d')
    query = session.query(func.count(), to_days, models.BadReplicas.rse_id, models.BadReplicas.state, models.BadReplicas.reason)
    # To be added : HINTS
    if rse_clause != []:
        query = query.filter(or_(*rse_clause))
    if from_date:
        query = query.filter(models.BadReplicas.created_at > from_date)
    if to_date:
        query = query.filter(models.BadReplicas.created_at < to_date)
    summary = query.group_by(to_days, models.BadReplicas.rse_id, models.BadReplicas.reason, models.BadReplicas.state).all()
    for row in summary:
        if (row[2], row[1], row[4]) not in incidents:
            incidents[(row[2], row[1], row[4])] = {}
        incidents[(row[2], row[1], row[4])][str(row[3].name)] = row[0]

    for incident in incidents:
        res = incidents[incident]
        res['rse_id'] = incident[0]
        res['rse'] = get_rse_name(rse_id=incident[0], session=session)
        res['created_at'] = incident[1]
        res['reason'] = incident[2]
        result.append(res)

    return result


@read_session
def __exists_replicas(rse_id, scope=None, name=None, path=None, session=None):
    """
    Internal method to check if a replica exists at a given site.
    :param rse_id: The RSE id.
    :param scope: The scope of the file.
    :param name: The name of the file.
    :param path: The path of the replica.
    :param session: The database session in use.
    """

    already_declared = False
    if path:
        path_clause = [models.RSEFileAssociation.path == path]
        if path.startswith('/'):
            path_clause.append(models.RSEFileAssociation.path == path[1:])
        else:
            path_clause.append(models.RSEFileAssociation.path == '/%s' % path)
        query = session.query(models.RSEFileAssociation.path, models.RSEFileAssociation.scope, models.RSEFileAssociation.name, models.RSEFileAssociation.rse_id, models.RSEFileAssociation.bytes).\
            with_hint(models.RSEFileAssociation, "+ index(replicas REPLICAS_PATH_IDX", 'oracle').\
            filter(models.RSEFileAssociation.rse_id == rse_id).filter(or_(*path_clause))
    else:
        query = session.query(models.RSEFileAssociation.path, models.RSEFileAssociation.scope, models.RSEFileAssociation.name, models.RSEFileAssociation.rse_id, models.RSEFileAssociation.bytes).\
            filter_by(rse_id=rse_id, scope=scope, name=name)
    if query.count():
        result = query.first()
        path, scope, name, rse_id, size = result
        # Now we check that the replica is not already declared bad
        query = session.query(models.BadReplicas.scope, models.BadReplicas.name, models.BadReplicas.rse_id, models.BadReplicas.state).\
            filter_by(rse_id=rse_id, scope=scope, name=name, state=BadFilesStatus.BAD)
        if query.count():
            already_declared = True
        return True, scope, name, already_declared, size
    else:
        return False, None, None, already_declared, None


@read_session
def list_bad_replicas_status(state=BadFilesStatus.BAD, rse_id=None, younger_than=None, older_than=None, limit=None, list_pfns=False, vo='def', session=None):
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
    query = session.query(models.BadReplicas.scope, models.BadReplicas.name, models.BadReplicas.rse_id, models.BadReplicas.state, models.BadReplicas.created_at, models.BadReplicas.updated_at)
    if state:
        query = query.filter(models.BadReplicas.state == state)
    if rse_id:
        query = query.filter(models.BadReplicas.rse_id == rse_id)
    if younger_than:
        query = query.filter(models.BadReplicas.created_at >= younger_than)
    if older_than:
        query = query.filter(models.BadReplicas.created_at <= older_than)
    if limit:
        query = query.limit(limit)

    for badfile in query.yield_per(1000):
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


@read_session
def list_bad_replicas_history(limit=10000, thread=None, total_threads=None, session=None):
    """
    List the bad file replicas history. Method only used by necromancer

    :param limit: The maximum number of replicas returned.
    :param thread: The assigned thread for this necromancer.
    :param total_threads: The total number of threads of all necromancers.
    :param session: The database session in use.
    """

    query = session.query(models.BadReplicas.scope, models.BadReplicas.name, models.BadReplicas.rse_id).\
        filter(models.BadReplicas.state == BadFilesStatus.BAD)
    query = filter_thread_work(session=session, query=query, total_threads=total_threads, thread_id=thread, hash_variable='name')
    query = query.limit(limit)

    bad_replicas = {}
    for scope, name, rse_id in query.yield_per(1000):
        if rse_id not in bad_replicas:
            bad_replicas[rse_id] = []
        bad_replicas[rse_id].append({'scope': scope, 'name': name})
    return bad_replicas


@transactional_session
def update_bad_replicas_history(dids, rse_id, session=None):
    """
    Update the bad file replicas history. Method only used by necromancer

    :param dids: The list of DIDs.
    :param rse_id: The rse_id.
    :param session: The database session in use.
    """

    for did in dids:
        # Check if the replica is still there
        try:
            result = session.query(models.RSEFileAssociation.state).filter_by(rse_id=rse_id, scope=did['scope'], name=did['name']).one()
            state = result.state
            if state == ReplicaState.AVAILABLE:
                # If yes, and replica state is AVAILABLE, update BadReplicas
                query = session.query(models.BadReplicas).filter_by(state=BadFilesStatus.BAD, rse_id=rse_id, scope=did['scope'], name=did['name'])
                query.update({'state': BadFilesStatus.RECOVERED, 'updated_at': datetime.utcnow()}, synchronize_session=False)
            elif state != ReplicaState.BAD:
                # If the replica state is not AVAILABLE check if other replicas for the same file are still there.
                try:
                    session.query(models.RSEFileAssociation.state).filter_by(rse_id=rse_id, scope=did['scope'], name=did['name'], state=ReplicaState.AVAILABLE).one()
                except NoResultFound:
                    # No replicas are available for this file. Reset the replica state to BAD
                    update_replicas_states([{'scope': did['scope'], 'name': did['name'], 'rse_id': rse_id, 'state': ReplicaState.BAD}], session=session)
                    session.query(models.Source).filter_by(scope=did['scope'], name=did['name'], rse_id=rse_id).delete(synchronize_session=False)
            else:
                # Here that means that the file has not been processed by the necro. Just pass
                pass
        except NoResultFound:
            # We end-up here if the replica is not registered anymore on the RSE
            try:
                result = session.query(models.DataIdentifier.availability).filter_by(scope=did['scope'], name=did['name'], did_type=DIDType.FILE).one()
                # If yes, the final state depends on DIDAvailability
                state = result.availability
                final_state = None
                if state == DIDAvailability.LOST:
                    final_state = BadFilesStatus.LOST
                elif state == DIDAvailability.DELETED:
                    final_state = BadFilesStatus.DELETED
                elif state == DIDAvailability.AVAILABLE:
                    final_state = BadFilesStatus.DELETED
                else:
                    # For completness, it shouldn't happen.
                    print('Houston we have a problem.')
                    final_state = BadFilesStatus.DELETED
                query = session.query(models.BadReplicas).filter_by(state=BadFilesStatus.BAD, rse_id=rse_id, scope=did['scope'], name=did['name'])
                query.update({'state': final_state, 'updated_at': datetime.utcnow()}, synchronize_session=False)
            except NoResultFound:
                # If no, the replica is marked as LOST in BadFilesStatus
                query = session.query(models.BadReplicas).filter_by(state=BadFilesStatus.BAD, rse_id=rse_id, scope=did['scope'], name=did['name'])
                query.update({'state': BadFilesStatus.LOST, 'updated_at': datetime.utcnow()}, synchronize_session=False)


@transactional_session
def __declare_bad_file_replicas(pfns, rse_id, reason, issuer, status=BadFilesStatus.BAD, scheme='srm', session=None):
    """
    Declare a list of bad replicas.

    :param pfns: The list of PFNs.
    :param rse_id: The RSE id.
    :param reason: The reason of the loss.
    :param issuer: The issuer account.
    :param status: Either BAD or SUSPICIOUS.
    :param scheme: The scheme of the PFNs.
    :param session: The database session in use.
    """
    unknown_replicas = []
    declared_replicas = []
    rse_info = rsemgr.get_rse_info(rse_id=rse_id, session=session)
    replicas = []
    proto = rsemgr.create_protocol(rse_info, 'read', scheme=scheme)
    if rse_info['deterministic']:
        parsed_pfn = proto.parse_pfns(pfns=pfns)
        for pfn in parsed_pfn:
            # WARNING : this part is ATLAS specific and must be changed
            path = parsed_pfn[pfn]['path']
            if path.startswith('/user') or path.startswith('/group'):
                scope = '%s.%s' % (path.split('/')[1], path.split('/')[2])
                name = parsed_pfn[pfn]['name']
            elif path.startswith('/'):
                scope = path.split('/')[1]
                name = parsed_pfn[pfn]['name']
            else:
                scope = path.split('/')[0]
                name = parsed_pfn[pfn]['name']

            scope = InternalScope(scope, vo=issuer.vo)

            __exists, scope, name, already_declared, size = __exists_replicas(rse_id, scope, name, path=None, session=session)
            if __exists and ((status == BadFilesStatus.BAD and not already_declared) or status == BadFilesStatus.SUSPICIOUS):
                replicas.append({'scope': scope, 'name': name, 'rse_id': rse_id, 'state': ReplicaState.BAD})
                new_bad_replica = models.BadReplicas(scope=scope, name=name, rse_id=rse_id, reason=reason, state=status, account=issuer, bytes=size)
                new_bad_replica.save(session=session, flush=False)
                session.query(models.Source).filter_by(scope=scope, name=name, rse_id=rse_id).delete(synchronize_session=False)
                declared_replicas.append(pfn)
            else:
                if already_declared:
                    unknown_replicas.append('%s %s' % (pfn, 'Already declared'))
                else:
                    no_hidden_char = True
                    for char in str(pfn):
                        if not isprint(char):
                            unknown_replicas.append('%s %s' % (pfn, 'PFN contains hidden chars'))
                            no_hidden_char = False
                            break
                    if no_hidden_char:
                        unknown_replicas.append('%s %s' % (pfn, 'Unknown replica'))
        if status == BadFilesStatus.BAD:
            # For BAD file, we modify the replica state, not for suspicious
            try:
                # there shouldn't be any exceptions since all replicas exist
                update_replicas_states(replicas, session=session)
            except exception.UnsupportedOperation:
                raise exception.ReplicaNotFound("One or several replicas don't exist.")
    else:
        path_clause = []
        parsed_pfn = proto.parse_pfns(pfns=pfns)
        for pfn in parsed_pfn:
            path = '%s%s' % (parsed_pfn[pfn]['path'], parsed_pfn[pfn]['name'])
            __exists, scope, name, already_declared, size = __exists_replicas(rse_id, scope=None, name=None, path=path, session=session)
            if __exists and ((status == BadFilesStatus.BAD and not already_declared) or status == BadFilesStatus.SUSPICIOUS):
                replicas.append({'scope': scope, 'name': name, 'rse_id': rse_id, 'state': ReplicaState.BAD})
                new_bad_replica = models.BadReplicas(scope=scope, name=name, rse_id=rse_id, reason=reason, state=status, account=issuer, bytes=size)
                new_bad_replica.save(session=session, flush=False)
                session.query(models.Source).filter_by(scope=scope, name=name, rse_id=rse_id).delete(synchronize_session=False)
                declared_replicas.append(pfn)
                path_clause.append(models.RSEFileAssociation.path == path)
                if path.startswith('/'):
                    path_clause.append(models.RSEFileAssociation.path == path[1:])
                else:
                    path_clause.append(models.RSEFileAssociation.path == '/%s' % path)
            else:
                if already_declared:
                    unknown_replicas.append('%s %s' % (pfn, 'Already declared'))
                else:
                    no_hidden_char = True
                    for char in str(pfn):
                        if not isprint(char):
                            unknown_replicas.append('%s %s' % (pfn, 'PFN contains hidden chars'))
                            no_hidden_char = False
                            break
                    if no_hidden_char:
                        unknown_replicas.append('%s %s' % (pfn, 'Unknown replica'))

        if status == BadFilesStatus.BAD and declared_replicas != []:
            # For BAD file, we modify the replica state, not for suspicious
            query = session.query(models.RSEFileAssociation) \
                .with_hint(models.RSEFileAssociation, "+ index(replicas REPLICAS_PATH_IDX", 'oracle') \
                .filter(models.RSEFileAssociation.rse_id == rse_id) \
                .filter(or_(*path_clause))
            rowcount = query.update({'state': ReplicaState.BAD})
            if rowcount != len(declared_replicas):
                # there shouldn't be any exceptions since all replicas exist
                print(rowcount, len(declared_replicas), declared_replicas)
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
def add_bad_dids(dids, rse_id, reason, issuer, state=BadFilesStatus.BAD, session=None):
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

    for did in dids:
        scope = InternalScope(did['scope'], vo=issuer.vo)
        name = did['name']
        replica_exists, _scope, _name, already_declared, size = __exists_replicas(rse_id, scope, name, path=None,
                                                                                  session=session)
        if replica_exists and not already_declared:
            replicas_for_update.append({'scope': scope, 'name': name, 'rse_id': rse_id, 'state': ReplicaState.BAD})
            new_bad_replica = models.BadReplicas(scope=scope, name=name, rse_id=rse_id, reason=reason, state=state,
                                                 account=issuer, bytes=size)
            new_bad_replica.save(session=session, flush=False)
            session.query(models.Source).filter_by(scope=scope, name=name,
                                                   rse_id=rse_id).delete(synchronize_session=False)
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
def declare_bad_file_replicas(pfns, reason, issuer, status=BadFilesStatus.BAD, session=None):
    """
    Declare a list of bad replicas.

    :param pfns: The list of PFNs.
    :param reason: The reason of the loss.
    :param issuer: The issuer account.
    :param status: The status of the file (SUSPICIOUS or BAD).
    :param session: The database session in use.
    """
    scheme, files_to_declare, unknown_replicas = get_pfn_to_rse(pfns, vo=issuer.vo, session=session)
    for rse_id in files_to_declare:
        notdeclared = __declare_bad_file_replicas(files_to_declare[rse_id], rse_id, reason, issuer, status=status, scheme=scheme, session=session)
        if notdeclared:
            unknown_replicas[rse_id] = notdeclared
    return unknown_replicas


@read_session
def get_pfn_to_rse(pfns, vo='def', session=None):
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
    surls = clean_surls(pfns)
    scheme = surls[0].split(':')[0] if surls else None
    for surl in surls:
        if surl.split(':')[0] != scheme:
            raise exception.InvalidType('The PFNs specified must have the same protocol')

        split_se = surl.split('/')[2].split(':')
        storage_element = split_se[0]

        if storage_element not in storage_elements:
            storage_elements.append(storage_element)
            se_condition.append(models.RSEProtocols.hostname == storage_element)
    query = session.query(models.RSEProtocols.rse_id, models.RSEProtocols.scheme, models.RSEProtocols.hostname, models.RSEProtocols.port, models.RSEProtocols.prefix).\
        filter(and_(or_(*se_condition), models.RSEProtocols.scheme == scheme)).filter(models.RSE.staging_area == false())
    protocols = {}

    for rse_id, protocol, hostname, port, prefix in query.yield_per(10000):
        protocols[rse_id] = ('%s://%s%s' % (protocol, hostname, prefix), '%s://%s:%s%s' % (protocol, hostname, port, prefix))
    hint = None
    for surl in surls:
        if hint and (surl.find(protocols[hint][0]) > -1 or surl.find(protocols[hint][1]) > -1):
            dict_rse[hint].append(surl)
        else:
            mult_rse_match = 0
            for rse_id in protocols:
                if (surl.find(protocols[rse_id][0]) > -1 or surl.find(protocols[rse_id][1]) > -1) and get_rse_vo(rse_id=rse_id, session=session) == vo:
                    mult_rse_match += 1
                    if mult_rse_match > 1:
                        print('ERROR, multiple matches : %s at %s' % (surl, rse_id))
                        raise exception.RucioException('ERROR, multiple matches : %s at %s' % (surl, get_rse_name(rse_id=rse_id, session=session)))
                    hint = rse_id
                    if hint not in dict_rse:
                        dict_rse[hint] = []
                    dict_rse[hint].append(surl)
            if mult_rse_match == 0:
                if 'unknown' not in unknown_replicas:
                    unknown_replicas['unknown'] = []
                unknown_replicas['unknown'].append(surl)
    return scheme, dict_rse, unknown_replicas


@read_session
def list_bad_replicas(limit=10000, thread=None, total_threads=None, session=None):
    """
    List RSE File replicas with no locks.

    :param limit: The maximum number of replicas returned.
    :param thread: The assigned thread for this necromancer.
    :param total_threads: The total number of threads of all necromancers.
    :param session: The database session in use.

    :returns: a list of dictionary {'scope' scope, 'name': name, 'rse_id': rse_id, 'rse': rse}.
    """
    schema_dot = '%s.' % DEFAULT_SCHEMA_NAME if DEFAULT_SCHEMA_NAME else ''
    if session.bind.dialect.name == 'oracle':
        # The filter(text...)) is needed otherwise, SQLA uses bind variables and the index is not used.
        query = session.query(models.RSEFileAssociation.scope,
                              models.RSEFileAssociation.name,
                              models.RSEFileAssociation.rse_id).\
            with_hint(models.RSEFileAssociation, "+ index(replicas REPLICAS_STATE_IDX)", 'oracle').\
            filter(text("CASE WHEN (%sreplicas.state != 'A') THEN %sreplicas.rse_id END IS NOT NULL" % (schema_dot,
                                                                                                        schema_dot))). \
            filter(models.RSEFileAssociation.state == ReplicaState.BAD)
    else:
        query = session.query(models.RSEFileAssociation.scope,
                              models.RSEFileAssociation.name,
                              models.RSEFileAssociation.rse_id).\
            filter(models.RSEFileAssociation.state == ReplicaState.BAD)

    query = filter_thread_work(session=session, query=query, total_threads=total_threads, thread_id=thread, hash_variable='%sreplicas.name' % (schema_dot))
    query = query.join(models.DataIdentifier,
                       and_(models.DataIdentifier.scope == models.RSEFileAssociation.scope,
                            models.DataIdentifier.name == models.RSEFileAssociation.name)).\
        filter(models.DataIdentifier.availability != DIDAvailability.LOST)

    query = query.limit(limit)
    rows = []
    for scope, name, rse_id in query.yield_per(1000):
        rows.append({'scope': scope, 'name': name, 'rse_id': rse_id, 'rse': get_rse_name(rse_id=rse_id, session=session)})
    return rows


@stream_session
def get_did_from_pfns(pfns, rse_id=None, vo='def', session=None):
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
            parsed_pfn = proto.parse_pfns(pfns=pfns)

            # WARNING : this part is ATLAS specific and must be changed
            for pfn in parsed_pfn:
                path = parsed_pfn[pfn]['path']
                if path.startswith('/user') or path.startswith('/group'):
                    scope = '%s.%s' % (path.split('/')[1], path.split('/')[2])
                    name = parsed_pfn[pfn]['name']
                elif path.startswith('/'):
                    scope = path.split('/')[1]
                    name = parsed_pfn[pfn]['name']
                else:
                    scope = path.split('/')[0]
                    name = parsed_pfn[pfn]['name']
                scope = InternalScope(scope, vo)
                yield {pfn: {'scope': scope, 'name': name}}
        else:
            condition = []
            parsed_pfn = proto.parse_pfns(pfns=pfns)
            for pfn in parsed_pfn:
                path = '%s%s' % (parsed_pfn[pfn]['path'], parsed_pfn[pfn]['name'])
                pfndict[path] = pfn
                condition.append(and_(models.RSEFileAssociation.path == path, models.RSEFileAssociation.rse_id == rse_id))
            for scope, name, pfn in session.query(models.RSEFileAssociation.scope, models.RSEFileAssociation.name, models.RSEFileAssociation.path).filter(or_(*condition)):
                yield {pfndict[pfn]: {'scope': scope, 'name': name}}


def _resolve_dids(dids, unavailable, ignore_availability, all_states, resolve_archives, session):
    """
    Resolve list of DIDs into a list of conditions.

    :param dids: The list of data identifiers (DIDs).
    :param unavailable: (deprecated) Also include unavailable replicas in the list.
    :param ignore_availability: Ignore the RSE blocklisting.
    :param all_states: Return all replicas whatever state they are in. Adds an extra 'states' entry in the result dictionary.
    :param resolve_archives: When set to true, find archives which contain the replicas.
    :param session: The database session in use.
    """
    did_clause, dataset_clause, file_clause, constituent_clause = [], [], [], []
    # Accumulate all the dids which were requested explicitly (not via a container/dataset).
    # If any replicas for these dids will be found latter, the associated did will be removed from the list,
    # leaving, at the end, only the requested dids which didn't have any replicas at all.
    files_wo_replica = []
    for did in [dict(tupleized) for tupleized in set(tuple(item.items()) for item in dids)]:
        if 'type' in did and did['type'] in (DIDType.FILE, DIDType.FILE.value) or 'did_type' in did and did['did_type'] in (DIDType.FILE, DIDType.FILE.value):  # pylint: disable=no-member
            files_wo_replica.append({'scope': did['scope'], 'name': did['name']})
            file_clause.append(and_(models.RSEFileAssociation.scope == did['scope'],
                                    models.RSEFileAssociation.name == did['name']))

        else:
            did_clause.append(and_(models.DataIdentifier.scope == did['scope'],
                                   models.DataIdentifier.name == did['name']))

    if did_clause:
        for scope, name, did_type, constituent in session.query(models.DataIdentifier.scope,
                                                                models.DataIdentifier.name,
                                                                models.DataIdentifier.did_type,
                                                                models.DataIdentifier.constituent)\
                                                         .with_hint(models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle')\
                                                         .filter(or_(*did_clause)):
            if resolve_archives and constituent:
                constituent_clause.append(and_(models.ConstituentAssociation.child_scope == scope,
                                               models.ConstituentAssociation.child_name == name))

            if did_type == DIDType.FILE:
                files_wo_replica.append({'scope': scope, 'name': name})
                file_clause.append(and_(models.RSEFileAssociation.scope == scope,
                                        models.RSEFileAssociation.name == name))

            elif did_type == DIDType.DATASET:
                dataset_clause.append(and_(models.DataIdentifierAssociation.scope == scope,
                                           models.DataIdentifierAssociation.name == name))

            else:  # Container
                content_query = session.query(models.DataIdentifierAssociation.child_scope,
                                              models.DataIdentifierAssociation.child_name,
                                              models.DataIdentifierAssociation.child_type)
                content_query = content_query.with_hint(models.DataIdentifierAssociation, "INDEX(CONTENTS CONTENTS_PK)", 'oracle')
                child_dids = [(scope, name)]
                while child_dids:
                    s, n = child_dids.pop()
                    for tmp_did in content_query.filter_by(scope=s, name=n):
                        if tmp_did.child_type == DIDType.DATASET:
                            dataset_clause.append(and_(models.DataIdentifierAssociation.scope == tmp_did.child_scope,
                                                       models.DataIdentifierAssociation.name == tmp_did.child_name))

                        else:
                            child_dids.append((tmp_did.child_scope, tmp_did.child_name))

    state_clause = None
    if not all_states:
        if not unavailable:
            state_clause = and_(models.RSEFileAssociation.state == ReplicaState.AVAILABLE)

        else:
            state_clause = or_(models.RSEFileAssociation.state == ReplicaState.AVAILABLE,
                               models.RSEFileAssociation.state == ReplicaState.UNAVAILABLE,
                               models.RSEFileAssociation.state == ReplicaState.COPYING)

    return file_clause, dataset_clause, state_clause, constituent_clause, files_wo_replica


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

            index_to_substitute = random.randint(0, i)
            if index_to_substitute < nrandom:
                selected[index_to_substitute] = element
    except StopIteration:
        pass

    for r in selected:
        yield r


def _list_replicas_for_datasets(dataset_clause, state_clause, rse_clause, ignore_availability, updated_after, session):
    """
    List file replicas for a list of datasets.

    :param session: The database session in use.
    """
    if not dataset_clause:
        return

    replica_query = session.query(models.DataIdentifierAssociation.child_scope,
                                  models.DataIdentifierAssociation.child_name,
                                  models.DataIdentifierAssociation.bytes,
                                  models.DataIdentifierAssociation.md5,
                                  models.DataIdentifierAssociation.adler32,
                                  models.RSEFileAssociation.path,
                                  models.RSEFileAssociation.state,
                                  models.RSE.id,
                                  models.RSE.rse,
                                  models.RSE.rse_type,
                                  models.RSE.volatile).\
        with_hint(models.RSEFileAssociation,
                  text="INDEX_RS_ASC(CONTENTS CONTENTS_PK) INDEX_RS_ASC(REPLICAS REPLICAS_PK) NO_INDEX_FFS(CONTENTS CONTENTS_PK)",
                  dialect_name='oracle').\
        outerjoin(models.RSEFileAssociation,
                  and_(models.DataIdentifierAssociation.child_scope == models.RSEFileAssociation.scope,
                       models.DataIdentifierAssociation.child_name == models.RSEFileAssociation.name)).\
        join(models.RSE, models.RSE.id == models.RSEFileAssociation.rse_id).\
        filter(models.RSE.deleted == false()).\
        filter(or_(*dataset_clause)).\
        order_by(models.DataIdentifierAssociation.child_scope,
                 models.DataIdentifierAssociation.child_name)

    if not ignore_availability:
        replica_query = replica_query.filter(models.RSE.availability.in_((4, 5, 6, 7)))

    if state_clause is not None:
        replica_query = replica_query.filter(and_(state_clause))

    if rse_clause is not None:
        replica_query = replica_query.filter(or_(*rse_clause))

    if updated_after:
        replica_query = replica_query.filter(models.RSEFileAssociation.updated_at >= updated_after)

    for scope, name, bytes, md5, adler32, path, state, rse_id, rse, rse_type, volatile in replica_query.yield_per(500):
        yield scope, name, None, None, bytes, md5, adler32, path, state, rse_id, rse, rse_type, volatile


def _list_replicas_for_constituents(constituent_clause, state_clause, files_wo_replica, rse_clause, ignore_availability, updated_after, session):
    """
    List file replicas for archive constituents.
    """
    if not constituent_clause:
        return

    constituent_query = session.query(models.ConstituentAssociation.child_scope,
                                      models.ConstituentAssociation.child_name,
                                      models.ConstituentAssociation.scope,
                                      models.ConstituentAssociation.name,
                                      models.ConstituentAssociation.bytes,
                                      models.ConstituentAssociation.md5,
                                      models.ConstituentAssociation.adler32,
                                      models.RSEFileAssociation.path,
                                      models.RSEFileAssociation.state,
                                      models.RSE.id,
                                      models.RSE.rse,
                                      models.RSE.rse_type,
                                      models.RSE.volatile). \
        with_hint(models.RSEFileAssociation,
                  text="INDEX_RS_ASC(CONTENTS CONTENTS_PK) INDEX_RS_ASC(REPLICAS REPLICAS_PK) NO_INDEX_FFS(CONTENTS CONTENTS_PK)",
                  dialect_name='oracle'). \
        with_hint(models.ConstituentAssociation, "INDEX(ARCHIVE_CONTENTS ARCH_CONTENTS_PK)", 'oracle'). \
        outerjoin(models.RSEFileAssociation,
                  and_(models.ConstituentAssociation.scope == models.RSEFileAssociation.scope,
                       models.ConstituentAssociation.name == models.RSEFileAssociation.name)). \
        join(models.RSE, models.RSE.id == models.RSEFileAssociation.rse_id). \
        filter(models.RSE.deleted == false()). \
        filter(or_(*constituent_clause)). \
        order_by(models.ConstituentAssociation.child_scope,
                 models.ConstituentAssociation.child_name)

    if not ignore_availability:
        constituent_query = constituent_query.filter(models.RSE.availability.in_((4, 5, 6, 7)))

    if state_clause is not None:
        constituent_query = constituent_query.filter(and_(state_clause))

    if rse_clause is not None:
        constituent_query = constituent_query.filter(or_(*rse_clause))

    if updated_after:
        constituent_query = constituent_query.filter(models.RSEFileAssociation.updated_at >= updated_after)

    for replica in constituent_query.yield_per(500):
        scope, name = replica[0], replica[1]
        {'scope': scope, 'name': name} in files_wo_replica and files_wo_replica.remove({'scope': scope, 'name': name})
        yield replica


def _list_replicas_for_files(file_clause, state_clause, files_wo_replica, rse_clause, ignore_availability, updated_after, session):
    """
    List file replicas for a list of files.

    :param session: The database session in use.
    """
    if not file_clause:
        return

    for replica_condition in chunks(file_clause, 50):
        filters = [
            models.RSEFileAssociation.rse_id == models.RSE.id,
            models.RSE.deleted == false(),
            or_(*replica_condition),
        ]

        if not ignore_availability:
            filters.append(models.RSE.availability.in_((4, 5, 6, 7)))

        if state_clause is not None:
            filters.append(state_clause)

        if rse_clause:
            filters.append(or_(*rse_clause))

        if updated_after:
            filters.append(models.RSEFileAssociation.updated_at >= updated_after)

        replica_query = session.query(
            models.RSEFileAssociation.scope,
            models.RSEFileAssociation.name,
            models.RSEFileAssociation.bytes,
            models.RSEFileAssociation.md5,
            models.RSEFileAssociation.adler32,
            models.RSEFileAssociation.path,
            models.RSEFileAssociation.state,
            models.RSE.id,
            models.RSE.rse,
            models.RSE.rse_type,
            models.RSE.volatile,
        ) \
            .filter(and_(*filters)) \
            .order_by(models.RSEFileAssociation.scope, models.RSEFileAssociation.name) \
            .with_hint(models.RSEFileAssociation, text="INDEX(REPLICAS REPLICAS_PK)", dialect_name='oracle')

        for scope, name, bytes, md5, adler32, path, state, rse_id, rse, rse_type, volatile in replica_query.all():
            {'scope': scope, 'name': name} in files_wo_replica and files_wo_replica.remove({'scope': scope, 'name': name})
            yield scope, name, None, None, bytes, md5, adler32, path, state, rse_id, rse, rse_type, volatile


def _list_files_wo_replicas(files_wo_replica, session):
    if files_wo_replica:
        file_wo_clause = []
        for file in sorted(files_wo_replica, key=lambda f: (f['scope'], f['name'])):
            file_wo_clause.append(and_(models.DataIdentifier.scope == file['scope'],
                                       models.DataIdentifier.name == file['name']))
        files_wo_replicas_query = session.query(models.DataIdentifier.scope,
                                                models.DataIdentifier.name,
                                                models.DataIdentifier.bytes,
                                                models.DataIdentifier.md5,
                                                models.DataIdentifier.adler32).\
            filter_by(did_type=DIDType.FILE).filter(or_(*file_wo_clause)).\
            with_hint(models.DataIdentifier, text="INDEX(DIDS DIDS_PK)", dialect_name='oracle')

        for scope, name, bytes, md5, adler32 in files_wo_replicas_query:
            yield scope, name, bytes, md5, adler32


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
            response = requests.get('{}/serverRanges'.format(vp_endpoint), verify=False)
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


def _list_replicas(dataset_clause, file_clause, state_clause, show_pfns,
                   schemes, files_wo_replica, rse_clause, client_location, domain,
                   sign_urls, signature_lifetime, constituent_clause, resolve_parents,
                   updated_after, filters, ignore_availability,
                   session):

    # iterator which merges multiple sorted replica sources into a combine sorted result without loading everything into the memory
    replicas = heapq.merge(
        _list_replicas_for_datasets(dataset_clause, state_clause, rse_clause, ignore_availability, updated_after, session),
        _list_replicas_for_files(file_clause, state_clause, files_wo_replica, rse_clause, ignore_availability, updated_after, session),
        _list_replicas_for_constituents(constituent_clause, state_clause, files_wo_replica, rse_clause, ignore_availability, updated_after, session),
        key=lambda t: (t[0], t[1]),  # sort by scope, name
    )

    # we need to retain knowledge of the original domain selection by the user
    # in case we have to loop over replicas with a potential outgoing proxy
    original_domain = deepcopy(domain)

    # find all RSEs local to the client's location in autoselect mode (i.e., when domain is None)
    local_rses = []
    if domain is None:
        if client_location and 'site' in client_location and client_location['site']:
            try:
                local_rses = [rse['id'] for rse in parse_expression('site=%s' % client_location['site'], filter=filters, session=session)]
            except Exception:
                pass  # do not hard fail if site cannot be resolved or is empty

    file, tmp_protocols, rse_info, pfns_cache = {}, {}, {}, {}

    for scope, name, archive_scope, archive_name, bytes, md5, adler32, path, state, rse_id, rse, rse_type, volatile in replicas:

        pfns = []

        # reset the domain selection to original user's choice (as this could get overwritten each iteration)
        domain = deepcopy(original_domain)

        if show_pfns and rse_id:
            if rse_id not in rse_info:
                rse_info[rse_id] = rsemgr.get_rse_info(rse_id=rse_id, session=session)

            # assign scheme priorities, and don't forget to exclude disabled protocols
            # 0 in RSE protocol definition = disabled, 1 = highest priority
            rse_info[rse_id]['priority_wan'] = {p['scheme']: p['domains']['wan']['read'] for p in rse_info[rse_id]['protocols'] if p['domains']['wan']['read'] > 0}
            rse_info[rse_id]['priority_lan'] = {p['scheme']: p['domains']['lan']['read'] for p in rse_info[rse_id]['protocols'] if p['domains']['lan']['read'] > 0}

            # select the lan door in autoselect mode, otherwise use the wan door
            if domain is None:
                domain = 'wan'
                if local_rses and rse_id in local_rses:
                    domain = 'lan'

            if rse_id not in tmp_protocols:

                rse_schemes = schemes or []
                if not rse_schemes:
                    try:
                        if domain == 'all':
                            rse_schemes.append(rsemgr.select_protocol(rse_settings=rse_info[rse_id],
                                                                      operation='read',
                                                                      domain='wan')['scheme'])
                            rse_schemes.append(rsemgr.select_protocol(rse_settings=rse_info[rse_id],
                                                                      operation='read',
                                                                      domain='lan')['scheme'])
                        else:
                            rse_schemes.append(rsemgr.select_protocol(rse_settings=rse_info[rse_id],
                                                                      operation='read',
                                                                      domain=domain)['scheme'])
                    except exception.RSEProtocolNotSupported:
                        pass  # no need to be verbose
                    except Exception:
                        print(format_exc())

                if archive_scope and archive_name and 'root' not in rse_schemes:
                    rse_schemes.append('root')

                protocols = []
                for s in rse_schemes:
                    try:
                        if domain == 'all':
                            protocols.append(('lan', rsemgr.create_protocol(rse_settings=rse_info[rse_id],
                                                                            operation='read',
                                                                            scheme=s,
                                                                            domain='lan'),
                                              rse_info[rse_id]['priority_lan'][s]))
                            protocols.append(('wan', rsemgr.create_protocol(rse_settings=rse_info[rse_id],
                                                                            operation='read',
                                                                            scheme=s,
                                                                            domain='wan'),
                                              rse_info[rse_id]['priority_wan'][s]))
                        else:
                            protocols.append((domain, rsemgr.create_protocol(rse_settings=rse_info[rse_id],
                                                                             operation='read',
                                                                             scheme=s,
                                                                             domain=domain),
                                              rse_info[rse_id]['priority_%s' % domain][s]))
                    except exception.RSEProtocolNotSupported:
                        pass  # no need to be verbose
                    except Exception:
                        print(format_exc())

                tmp_protocols[rse_id] = protocols

            # get pfns
            for tmp_protocol in tmp_protocols[rse_id]:
                # If the current "replica" is a constituent inside an archive, we must construct the pfn for the
                # parent (archive) file and append the xrdcl.unzip query string to it.
                if archive_scope and archive_name:
                    t_scope = archive_scope
                    t_name = archive_name
                else:
                    t_scope = scope
                    t_name = name
                protocol = tmp_protocol[1]
                if 'determinism_type' in protocol.attributes:  # PFN is cachable
                    try:
                        path = pfns_cache['%s:%s:%s' % (protocol.attributes['determinism_type'], t_scope.internal, t_name)]
                    except KeyError:  # No cache entry scope:name found for this protocol
                        path = protocol._get_path(t_scope, t_name)
                        pfns_cache['%s:%s:%s' % (protocol.attributes['determinism_type'], t_scope.internal, t_name)] = path

                try:
                    pfn = list(protocol.lfns2pfns(lfns={'scope': t_scope.external,
                                                        'name': t_name,
                                                        'path': path}).values())[0]

                    # do we need to sign the URLs?
                    if sign_urls and protocol.attributes['scheme'] == 'https':
                        service = get_rse_attribute('sign_url',
                                                    rse_id=rse_id,
                                                    session=session)
                        if service and isinstance(service, list):
                            pfn = get_signed_url(rse_id=rse_id, service=service[0], operation='read', url=pfn, lifetime=signature_lifetime)

                    # server side root proxy handling if location is set.
                    # supports root and http destinations
                    # cannot be pushed into protocols because we need to lookup rse attributes.
                    # ultra-conservative implementation.
                    if domain == 'wan' and protocol.attributes['scheme'] in ['root', 'http', 'https'] and client_location:

                        if 'site' in client_location and client_location['site']:
                            # is the RSE site-configured?
                            rse_site_attr = get_rse_attribute('site', rse_id, session=session)
                            replica_site = ['']
                            if isinstance(rse_site_attr, list) and rse_site_attr:
                                replica_site = rse_site_attr[0]

                            # does it match with the client? if not, it's an outgoing connection
                            # therefore the internal proxy must be prepended
                            if client_location['site'] != replica_site:
                                cache_site = config_get('clientcachemap', client_location['site'], default='', session=session)
                                if cache_site != '':
                                    # print('client', client_location['site'], 'has cache:', cache_site)
                                    # print('filename', name)
                                    selected_prefix = get_multi_cache_prefix(cache_site, t_name)
                                    if selected_prefix:
                                        pfn = 'root://' + selected_prefix + '//' + pfn.replace('davs://', 'root://')
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
                                            pfn = 'root://' + root_proxy_internal + '//' + pfn.replace('davs://', 'https://')

                    # PFNs don't have concepts, therefore quickly encapsulate in a tuple
                    # ('pfn', 'domain', 'priority', 'client_extract')
                    t_domain = tmp_protocol[0]
                    t_priority = tmp_protocol[2]
                    t_client_extract = False
                    if archive_scope and archive_name:
                        t_domain = 'zip'
                        pfn = add_url_query(pfn, {'xrdcl.unzip': name})
                        if protocol.attributes['scheme'] == 'root':
                            # xroot supports downloading files directly from inside an archive. Disable client_extract and prioritize xroot.
                            t_client_extract = False
                            t_priority = -1
                        else:
                            t_client_extract = True
                    pfns.append((pfn, t_domain, t_priority, t_client_extract))
                except Exception:
                    # never end up here
                    print(format_exc())

                if protocol.attributes['scheme'] == 'srm':
                    try:
                        file['space_token'] = protocol.attributes['extended_attributes']['space_token']
                    except KeyError:
                        file['space_token'] = None

        if 'scope' in file and 'name' in file:
            if file['scope'] == scope and file['name'] == name:
                # extract properly the pfn from the tuple
                file['rses'][rse_id] += list(set([tmp_pfn[0] for tmp_pfn in pfns]))
                file['states'][rse_id] = str(state.name if state else state)

                if resolve_parents:
                    file['parents'] = ['%s:%s' % (parent['scope'].internal, parent['name'])
                                       for parent in rucio.core.did.list_all_parent_dids(scope, name, session=session)]

                for tmp_pfn in pfns:
                    file['pfns'][tmp_pfn[0]] = {'rse_id': rse_id,
                                                'rse': rse,
                                                'type': str(rse_type.name),
                                                'volatile': volatile,
                                                'domain': tmp_pfn[1],
                                                'priority': tmp_pfn[2],
                                                'client_extract': tmp_pfn[3]}
            else:
                if resolve_parents:
                    file['parents'] = ['%s:%s' % (parent['scope'].internal, parent['name'])
                                       for parent in rucio.core.did.list_all_parent_dids(file['scope'], file['name'], session=session)]

                # quick exit, but don't forget to set the total order for the priority
                # --> exploit that L(AN) comes before W(AN) before Z(IP) alphabetically
                # and use 1-indexing to be compatible with metalink
                tmp = sorted([(file['pfns'][p]['domain'], file['pfns'][p]['priority'], p) for p in file['pfns']])

                for i in range(0, len(tmp)):
                    file['pfns'][tmp[i][2]]['priority'] = i + 1
                    file['rses'] = {}

                    rse_pfns = []
                    for t_rse, t_priority, t_pfn in [(file['pfns'][t_pfn]['rse_id'], file['pfns'][t_pfn]['priority'], t_pfn) for t_pfn in file['pfns']]:
                        rse_pfns.append((t_rse, t_priority, t_pfn))
                    rse_pfns = sorted(rse_pfns)

                    for t_rse, t_priority, t_pfn in rse_pfns:
                        if t_rse in file['rses']:
                            file['rses'][t_rse].append(t_pfn)
                        else:
                            file['rses'][t_rse] = [t_pfn]

                yield file
                file = {}

        if not ('scope' in file and 'name' in file):
            file['scope'], file['name'] = scope, name
            file['bytes'], file['md5'], file['adler32'] = bytes, md5, adler32
            file['pfns'], file['rses'] = {}, defaultdict(list)
            file['states'] = {rse_id: str(state.name if state else state)}

            if resolve_parents:
                file['parents'] = ['%s:%s' % (parent['scope'].internal, parent['name'])
                                   for parent in rucio.core.did.list_all_parent_dids(scope, name, session=session)]

            if rse_id:
                # extract properly the pfn from the tuple
                file['rses'][rse_id] = list(set([tmp_pfn[0] for tmp_pfn in pfns]))
                for tmp_pfn in pfns:
                    file['pfns'][tmp_pfn[0]] = {'rse_id': rse_id,
                                                'rse': rse,
                                                'type': str(rse_type.name),
                                                'volatile': volatile,
                                                'domain': tmp_pfn[1],
                                                'priority': tmp_pfn[2],
                                                'client_extract': tmp_pfn[3]}

    # set the total order for the priority
    # --> exploit that L(AN) comes before W(AN) before Z(IP) alphabetically
    # and use 1-indexing to be compatible with metalink
    if 'pfns' in file:
        tmp = sorted([(file['pfns'][p]['domain'], file['pfns'][p]['priority'], p) for p in file['pfns']])
        for i in range(0, len(tmp)):
            file['pfns'][tmp[i][2]]['priority'] = i + 1

    if 'scope' in file and 'name' in file:
        file['rses'] = {}

        # don't forget to resolve parents for the last replica
        if resolve_parents:
            file['parents'] = ['%s:%s' % (parent['scope'].internal, parent['name'])
                               for parent in rucio.core.did.list_all_parent_dids(file['scope'], file['name'], session=session)]

        # also sort the pfns inside the rse structure
        rse_pfns = []
        for t_rse, t_priority, t_pfn in [(file['pfns'][t_pfn]['rse_id'], file['pfns'][t_pfn]['priority'], t_pfn) for t_pfn in file['pfns']]:
            rse_pfns.append((t_rse, t_priority, t_pfn))
        rse_pfns = sorted(rse_pfns)

        for t_rse, t_priority, t_pfn in rse_pfns:
            if t_rse in file['rses']:
                file['rses'][t_rse].append(t_pfn)
            else:
                file['rses'][t_rse] = [t_pfn]

        yield file
        file = {}

    for scope, name, bytes, md5, adler32 in _list_files_wo_replicas(files_wo_replica, session):
        yield {
            'scope': scope,
            'name': name,
            'bytes': bytes,
            'md5': md5,
            'adler32': adler32,
            'pfns': {},
            'rses': defaultdict(list)
        }


@stream_session
def list_replicas(dids, schemes=None, unavailable=False, request_id=None,
                  ignore_availability=True, all_states=False, pfns=True,
                  rse_expression=None, client_location=None, domain=None,
                  sign_urls=False, signature_lifetime=None, resolve_archives=True,
                  resolve_parents=False, nrandom=None,
                  updated_after=None,
                  session=None):
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
    :param session: The database session in use.
    """
    if dids:
        filter = {'vo': dids[0]['scope'].vo}
    else:
        filter = {'vo': 'def'}

    file_clause, dataset_clause, state_clause, constituent_clause, files_wo_replica = _resolve_dids(
        dids=dids,
        unavailable=unavailable,
        ignore_availability=ignore_availability,
        all_states=all_states,
        resolve_archives=resolve_archives,
        session=session
    )

    rse_clause = []
    if rse_expression:
        for rse in parse_expression(expression=rse_expression, filter=filter, session=session):
            rse_clause.append(models.RSEFileAssociation.rse_id == rse['id'])

    yield from _pick_n_random(
        nrandom,
        _list_replicas(dataset_clause, file_clause, state_clause, pfns,
                       schemes, files_wo_replica, rse_clause, client_location, domain,
                       sign_urls, signature_lifetime, constituent_clause, resolve_parents,
                       updated_after, filter, ignore_availability,
                       session)
    )


@transactional_session
def __bulk_add_new_file_dids(files, account, dataset_meta=None, session=None):
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
def __bulk_add_file_dids(files, account, dataset_meta=None, session=None):
    """
    Bulk add new dids.

    :param dids: the list of files.
    :param account: The account owner.
    :param session: The database session in use.
    :returns: True is successful.
    """
    condition = []
    for f in files:
        condition.append(and_(models.DataIdentifier.scope == f['scope'], models.DataIdentifier.name == f['name'], models.DataIdentifier.did_type == DIDType.FILE))

    q = session.query(models.DataIdentifier.scope,
                      models.DataIdentifier.name,
                      models.DataIdentifier.bytes,
                      models.DataIdentifier.adler32,
                      models.DataIdentifier.md5).with_hint(models.DataIdentifier, "INDEX(dids DIDS_PK)", 'oracle').filter(or_(*condition))
    available_files = [dict([(column, getattr(row, column)) for column in row._fields]) for row in q]
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

    if not isinstance(tombstone_delay, timedelta):
        try:
            tombstone_delay = timedelta(seconds=int(tombstone_delay))
        except ValueError:
            return None

    if not tombstone_delay:
        return None

    if tombstone_delay < timedelta(0):
        return datetime(1970, 1, 1)

    return datetime.utcnow() + tombstone_delay


@transactional_session
def __bulk_add_replicas(rse_id, files, account, session=None):
    """
    Bulk add new dids.

    :param rse_id: the RSE id.
    :param dids: the list of files.
    :param account: The account owner.
    :param session: The database session in use.
    :returns: True is successful.
    """
    nbfiles, bytes = 0, 0
    # Check for the replicas already available
    condition = []
    for f in files:
        condition.append(and_(models.RSEFileAssociation.scope == f['scope'], models.RSEFileAssociation.name == f['name'], models.RSEFileAssociation.rse_id == rse_id))

    query = session.query(models.RSEFileAssociation.scope, models.RSEFileAssociation.name, models.RSEFileAssociation.rse_id).\
        with_hint(models.RSEFileAssociation, text="INDEX(REPLICAS REPLICAS_PK)", dialect_name='oracle').\
        filter(or_(*condition))
    available_replicas = [dict([(column, getattr(row, column)) for column in row._fields]) for row in query]

    default_tombstone_delay = next(iter(get_rse_attribute('tombstone_delay', rse_id=rse_id, session=session)), None)
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
            bytes += file['bytes']
            new_replicas.append({'rse_id': rse_id, 'scope': file['scope'],
                                 'name': file['name'], 'bytes': file['bytes'],
                                 'path': file.get('path'),
                                 'state': ReplicaState(file.get('state', 'A')),
                                 'md5': file.get('md5'), 'adler32': file.get('adler32'),
                                 'lock_cnt': file.get('lock_cnt', 0),
                                 'tombstone': file.get('tombstone') or default_tombstone})
    try:
        new_replicas and session.bulk_insert_mappings(models.RSEFileAssociation,
                                                      new_replicas)
        session.flush()
        return nbfiles, bytes
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
                 dataset_meta=None, session=None):
    """
    Bulk add file replicas.

    :param rse_id:  The RSE id.
    :param files:   The list of files.
    :param account: The account owner.
    :param ignore_availability: Ignore the RSE blocklisting.
    :param session: The database session in use.

    :returns: True is successful.
    """

    def _expected_pfns(lfns, rse_settings, scheme, operation='write', domain='wan', protocol_attr=None):
        p = rsemgr.create_protocol(rse_settings=rse_settings, operation='write', scheme=scheme, domain=domain, protocol_attr=protocol_attr)
        expected_pfns = p.lfns2pfns(lfns)
        return clean_surls(expected_pfns.values())

    replica_rse = get_rse(rse_id=rse_id, session=session)

    if replica_rse.volatile is True:
        raise exception.UnsupportedOperation('Cannot add replicas on volatile RSE %s ' % (replica_rse.rse))

    if not (replica_rse.availability & 2) and not ignore_availability:
        raise exception.ResourceTemporaryUnavailable('%s is temporary unavailable for writing' % replica_rse.rse)

    replicas = __bulk_add_file_dids(files=files, account=account,
                                    dataset_meta=dataset_meta,
                                    session=session)

    pfns, scheme = {}, None  # {scheme: [pfns], scheme: [pfns]}
    for file in files:
        if 'pfn' not in file:
            if not replica_rse.deterministic:
                raise exception.UnsupportedOperation('PFN needed for this (non deterministic) RSE %s ' % (replica_rse.rse))
        else:
            scheme = file['pfn'].split(':')[0]
            pfns.setdefault(scheme, []).append(file['pfn'])

    if pfns:
        rse_settings = rsemgr.get_rse_info(rse_id=rse_id, session=session)
        for scheme in pfns.keys():
            if not replica_rse.deterministic:
                p = rsemgr.create_protocol(rse_settings=rse_settings, operation='write', scheme=scheme)
                pfns[scheme] = p.parse_pfns(pfns=pfns[scheme])
                for file in files:
                    if file['pfn'].startswith(scheme):
                        tmp = pfns[scheme][file['pfn']]
                        file['path'] = ''.join([tmp['path'], tmp['name']])
            else:
                # Check that the pfns match to the expected pfns
                lfns = [{'scope': i['scope'].external, 'name': i['name']} for i in files if i['pfn'].startswith(scheme)]
                pfns[scheme] = clean_surls(pfns[scheme])

                # Check wan first
                found_on_wan = False
                available_wan_protocols = rsemgr.get_protocols_ordered(rse_settings=rse_settings, operation='write', scheme=scheme, domain='wan')
                expected_pfns_wan = None
                for protocol_attr in available_wan_protocols:
                    pfns_wan_buffer = _expected_pfns(lfns, rse_settings, scheme, operation='write', domain='wan', protocol_attr=protocol_attr)
                    if not expected_pfns_wan and pfns_wan_buffer:
                        expected_pfns_wan = pfns_wan_buffer
                    found_on_wan = found_on_wan or (pfns_wan_buffer == pfns[scheme])
                    if found_on_wan:
                        break

                if not found_on_wan:
                    # Check lan
                    found_on_lan = False
                    available_lan_protocols = rsemgr.get_protocols_ordered(rse_settings=rse_settings, operation='write', scheme=scheme, domain='lan')
                    for protocol_attr in available_lan_protocols:
                        pfns_lan_buffer = _expected_pfns(lfns, rse_settings, scheme, operation='write', domain='lan', protocol_attr=protocol_attr)
                        found_on_lan = found_on_lan or (pfns_lan_buffer == pfns[scheme])
                        if found_on_lan:
                            break

                    if found_on_lan == pfns[scheme]:
                        # Registration always with wan
                        pfns[scheme] = expected_pfns_wan
                    else:
                        raise exception.InvalidPath('One of the PFNs provided does not match the Rucio expected PFN : got %s, expected %s (%s)' % (str(pfns), str(expected_pfns_wan), str(lfns)))

    nbfiles, bytes = __bulk_add_replicas(rse_id=rse_id, files=files, account=account, session=session)
    increase(rse_id=rse_id, files=nbfiles, bytes=bytes, session=session)
    return replicas


@transactional_session
def add_replica(rse_id, scope, name, bytes, account, adler32=None, md5=None, dsn=None, pfn=None, meta=None, rules=[], tombstone=None, session=None):
    """
    Add File replica.

    :param rse_id: the rse id.
    :param scope: the scope name.
    :param name: The data identifier name.
    :param bytes: the size of the file.
    :param account: The account owner.
    :param md5: The md5 checksum.
    :param adler32: The adler32 checksum.
    :param pfn: Physical file name (for nondeterministic rse).
    :param meta: Meta-data associated with the file. Represented as key/value pairs in a dictionary.
    :param rules: Replication rules associated with the file. A list of dictionaries, e.g., [{'copies': 2, 'rse_expression': 'TIERS1'}, ].
    :param tombstone: If True, create replica with a tombstone.
    :param session: The database session in use.

    :returns: True is successful.
    """
    if meta is None:
        meta = {}

    file = {'scope': scope, 'name': name, 'bytes': bytes, 'adler32': adler32, 'md5': md5, 'meta': meta, 'rules': rules, 'tombstone': tombstone}
    if pfn:
        file['pfn'] = pfn
    return add_replicas(rse_id=rse_id, files=[file, ], account=account, session=session)


@transactional_session
def delete_replicas(rse_id, files, ignore_availability=True, session=None):
    """
    Delete file replicas.

    :param rse_id: the rse id.
    :param files: the list of files to delete.
    :param ignore_availability: Ignore the RSE blocklisting.
    :param session: The database session in use.
    """
    replica_rse = get_rse(rse_id=rse_id, session=session)

    if not (replica_rse.availability & 1) and not ignore_availability:
        raise exception.ResourceTemporaryUnavailable('%s is temporary unavailable'
                                                     'for deleting' % replica_rse.rse)

    replica_condition, src_condition = [], []
    for file in files:
        replica_condition.append(
            and_(models.RSEFileAssociation.scope == file['scope'],
                 models.RSEFileAssociation.name == file['name']))

        src_condition.append(
            and_(models.Source.scope == file['scope'],
                 models.Source.name == file['name'],
                 models.Source.rse_id == rse_id))

    delta, bytes, rowcount = 0, 0, 0

    # WARNING : This should not be necessary since that would mean the replica is used as a source.
    for chunk in chunks(src_condition, 10):
        rowcount = session.query(models.Source). \
            filter(or_(*chunk)). \
            delete(synchronize_session=False)

    rowcount = 0
    for chunk in chunks(replica_condition, 10):
        for (scope, name, rid, replica_bytes) in session.query(models.RSEFileAssociation.scope, models.RSEFileAssociation.name, models.RSEFileAssociation.rse_id, models.RSEFileAssociation.bytes). \
                with_hint(models.RSEFileAssociation, "INDEX(REPLICAS REPLICAS_PK)", 'oracle').filter(models.RSEFileAssociation.rse_id == rse_id).filter(or_(*chunk)):
            bytes += replica_bytes
            delta += 1

        rowcount += session.query(models.RSEFileAssociation). \
            filter(models.RSEFileAssociation.rse_id == rse_id). \
            filter(or_(*chunk)). \
            delete(synchronize_session=False)

    if rowcount != len(files):
        raise exception.ReplicaNotFound("One or several replicas don't exist.")

    __cleanup_after_replica_deletion(rse_id=rse_id, files=files, session=session)

    # Decrease RSE counter
    decrease(rse_id=rse_id, files=delta, bytes=bytes, session=session)


@transactional_session
def __cleanup_after_replica_deletion(rse_id, files, session=None):
    """
    Perform update of collections/archive associations/dids after the removal of their replicas
    :param rse_id: the rse id
    :param files: list of files whose replica got deleted
    :param session: The database session in use.
    """
    parent_condition, did_condition = [], []
    clt_replica_condition, dst_replica_condition = [], []
    incomplete_condition, messages, clt_is_not_archive_condition, archive_contents_condition = [], [], [], []
    for file in files:

        # Schedule update of all collections containing this file and having a collection replica in the RSE
        dst_replica_condition.append(
            and_(models.DataIdentifierAssociation.child_scope == file['scope'],
                 models.DataIdentifierAssociation.child_name == file['name'],
                 exists(select([1]).prefix_with("/*+ INDEX(COLLECTION_REPLICAS COLLECTION_REPLICAS_PK) */", dialect='oracle')).where(
                     and_(models.CollectionReplica.scope == models.DataIdentifierAssociation.scope,
                          models.CollectionReplica.name == models.DataIdentifierAssociation.name,
                          models.CollectionReplica.rse_id == rse_id))))

        # If the file doesn't have any replicas anymore, we should perform cleanups of objects
        # related to this file. However, if the file is "lost", it's removal wasn't intentional,
        # so we want to skip deleting the metadata here. Perform cleanups:

        # 1) schedule removal of this file from all parent datasets
        parent_condition.append(
            and_(models.DataIdentifierAssociation.child_scope == file['scope'],
                 models.DataIdentifierAssociation.child_name == file['name'],
                 ~exists(select([1]).prefix_with("/*+ INDEX(DIDS DIDS_PK) */", dialect='oracle')).where(
                     and_(models.DataIdentifier.scope == file['scope'],
                          models.DataIdentifier.name == file['name'],
                          models.DataIdentifier.availability == DIDAvailability.LOST)),
                 ~exists(select([1]).prefix_with("/*+ INDEX(REPLICAS REPLICAS_PK) */", dialect='oracle')).where(
                     and_(models.RSEFileAssociation.scope == file['scope'],
                          models.RSEFileAssociation.name == file['name'])),
                 ~exists(select([1]).prefix_with("/*+ INDEX(ARCHIVE_CONTENTS ARCH_CONTENTS_PK) */", dialect='oracle')).where(
                     and_(models.ConstituentAssociation.child_scope == file['scope'],
                          models.ConstituentAssociation.child_name == file['name']))))

        # 2) schedule removal of this file from the DID table
        did_condition.append(
            and_(models.DataIdentifier.scope == file['scope'],
                 models.DataIdentifier.name == file['name'],
                 models.DataIdentifier.availability != DIDAvailability.LOST,
                 ~exists(select([1]).prefix_with("/*+ INDEX(REPLICAS REPLICAS_PK) */", dialect='oracle')).where(
                     and_(models.RSEFileAssociation.scope == file['scope'],
                          models.RSEFileAssociation.name == file['name'])),
                 ~exists(select([1]).prefix_with("/*+ INDEX(ARCHIVE_CONTENTS ARCH_CONTENTS_PK) */", dialect='oracle')).where(
                     and_(models.ConstituentAssociation.child_scope == file['scope'],
                          models.ConstituentAssociation.child_name == file['name']))))

        # 3) if the file is an archive, schedule cleanup on the files from inside the archive
        archive_contents_condition.append(
            and_(models.ConstituentAssociation.scope == file['scope'],
                 models.ConstituentAssociation.name == file['name'],
                 ~exists(select([1]).prefix_with("/*+ INDEX(DIDS DIDS_PK) */", dialect='oracle')).where(
                     and_(models.DataIdentifier.scope == file['scope'],
                          models.DataIdentifier.name == file['name'],
                          models.DataIdentifier.availability == DIDAvailability.LOST)),
                 ~exists(select([1]).prefix_with("/*+ INDEX(REPLICAS REPLICAS_PK) */", dialect='oracle')).where(
                     and_(models.RSEFileAssociation.scope == file['scope'],
                          models.RSEFileAssociation.name == file['name']))))

    # Get all collection_replicas at RSE, insert them into UpdatedCollectionReplica
    if dst_replica_condition:
        for chunk in chunks(dst_replica_condition, 10):
            query = session.query(models.DataIdentifierAssociation.scope, models.DataIdentifierAssociation.name).\
                filter(or_(*chunk)).\
                distinct()

            for parent_scope, parent_name in query:
                models.UpdatedCollectionReplica(scope=parent_scope,
                                                name=parent_name,
                                                did_type=DIDType.DATASET,
                                                rse_id=rse_id).\
                    save(session=session, flush=False)

    # Delete did from the content for the last did
    while parent_condition:
        child_did_condition, tmp_parent_condition = [], []
        for chunk in chunks(parent_condition, 10):

            query = session.query(models.DataIdentifierAssociation.scope, models.DataIdentifierAssociation.name,
                                  models.DataIdentifierAssociation.did_type,
                                  models.DataIdentifierAssociation.child_scope, models.DataIdentifierAssociation.child_name).\
                filter(or_(*chunk))
            for parent_scope, parent_name, did_type, child_scope, child_name in query:

                # Schedule removal of child file/dataset/container from the parent dataset/container
                child_did_condition.append(
                    and_(models.DataIdentifierAssociation.scope == parent_scope,
                         models.DataIdentifierAssociation.name == parent_name,
                         models.DataIdentifierAssociation.child_scope == child_scope,
                         models.DataIdentifierAssociation.child_name == child_name))

                # Schedule setting is_archive = False on parents which don't have any children with is_archive == True anymore
                clt_is_not_archive_condition.append(
                    and_(models.DataIdentifierAssociation.scope == parent_scope,
                         models.DataIdentifierAssociation.name == parent_name,
                         exists(select([1]).prefix_with("/*+ INDEX(DIDS DIDS_PK) */", dialect='oracle')).where(
                             and_(models.DataIdentifier.scope == models.DataIdentifierAssociation.scope,
                                  models.DataIdentifier.name == models.DataIdentifierAssociation.name,
                                  models.DataIdentifier.is_archive == true())),
                         ~exists(select([1]).prefix_with("/*+ INDEX(DIDS DIDS_PK) */", dialect='oracle')).where(
                             and_(models.DataIdentifier.scope == models.DataIdentifierAssociation.child_scope,
                                  models.DataIdentifier.name == models.DataIdentifierAssociation.child_name,
                                  models.DataIdentifier.is_archive == true()))))

                # If the parent dataset/container becomes empty as a result of the child removal
                # (it was the last children), metadata cleanup has to be done:
                #
                # 1) Schedule to remove the replicas of this empty collection
                clt_replica_condition.append(
                    and_(models.CollectionReplica.scope == parent_scope,
                         models.CollectionReplica.name == parent_name,
                         exists(select([1]).prefix_with("/*+ INDEX(DIDS DIDS_PK) */", dialect='oracle')).where(
                             and_(models.DataIdentifier.scope == parent_scope,
                                  models.DataIdentifier.name == parent_name,
                                  models.DataIdentifier.is_open == False)),  # NOQA
                         ~exists(select([1]).prefix_with("/*+ INDEX(CONTENTS CONTENTS_PK) */", dialect='oracle')).where(
                             and_(models.DataIdentifierAssociation.scope == parent_scope,
                                  models.DataIdentifierAssociation.name == parent_name))))

                # 2) Schedule removal of this empty collection from its own parent collections
                tmp_parent_condition.append(
                    and_(models.DataIdentifierAssociation.child_scope == parent_scope,
                         models.DataIdentifierAssociation.child_name == parent_name,
                         ~exists(select([1]).prefix_with("/*+ INDEX(CONTENTS CONTENTS_PK) */", dialect='oracle')).where(
                             and_(models.DataIdentifierAssociation.scope == parent_scope,
                                  models.DataIdentifierAssociation.name == parent_name))))

                # 3) Schedule removal of the entry from the DIDs table
                did_condition.append(
                    and_(models.DataIdentifier.scope == parent_scope,
                         models.DataIdentifier.name == parent_name,
                         models.DataIdentifier.is_open == False,  # NOQA
                         ~exists([1]).where(
                             and_(models.DataIdentifierAssociation.child_scope == parent_scope,
                                  models.DataIdentifierAssociation.child_name == parent_name)),
                         ~exists([1]).where(
                             and_(models.DataIdentifierAssociation.scope == parent_scope,
                                  models.DataIdentifierAssociation.name == parent_name))))

        if child_did_condition:

            # get the list of modified parent scope, name
            for chunk in chunks(child_did_condition, 10):
                modifieds = session.query(models.DataIdentifierAssociation.scope,
                                          models.DataIdentifierAssociation.name,
                                          models.DataIdentifierAssociation.did_type).\
                    distinct().\
                    with_hint(models.DataIdentifierAssociation, "INDEX(CONTENTS CONTENTS_PK)", 'oracle').\
                    filter(or_(*chunk)).\
                    filter(exists(select([1]).
                                  prefix_with("/*+ INDEX(DIDS DIDS_PK) */", dialect='oracle')).
                           where(and_(models.DataIdentifierAssociation.scope == models.DataIdentifier.scope,
                                      models.DataIdentifierAssociation.name == models.DataIdentifier.name,
                                      or_(models.DataIdentifier.complete == true(),
                                          models.DataIdentifier.complete is None))))
                for parent_scope, parent_name, parent_did_type in modifieds:
                    message = {'scope': parent_scope,
                               'name': parent_name,
                               'did_type': parent_did_type,
                               'event_type': 'INCOMPLETE'}
                    if message not in messages:
                        messages.append(message)
                        incomplete_condition.append(
                            and_(models.DataIdentifier.scope == parent_scope,
                                 models.DataIdentifier.name == parent_name,
                                 models.DataIdentifier.did_type == parent_did_type))

            for chunk in chunks(child_did_condition, 10):
                rucio.core.did.insert_content_history(content_clause=chunk, did_created_at=None, session=session)
                session.query(models.DataIdentifierAssociation).\
                    filter(or_(*chunk)).\
                    delete(synchronize_session=False)

        parent_condition = tmp_parent_condition

    for chunk in chunks(clt_replica_condition, 10):
        session.query(models.CollectionReplica).\
            filter(or_(*chunk)).\
            delete(synchronize_session=False)

    # Update incomplete state
    for chunk in chunks(incomplete_condition, 10):
        session.query(models.DataIdentifier).\
            with_hint(models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle').\
            filter(or_(*chunk)).\
            filter(models.DataIdentifier.complete != false()).\
            update({'complete': False}, synchronize_session=False)

    # delete empty dids
    messages, deleted_dids, deleted_rules, deleted_did_meta = [], [], [], []
    for chunk in chunks(did_condition, 100):
        query = session.query(models.DataIdentifier.scope,
                              models.DataIdentifier.name,
                              models.DataIdentifier.did_type).\
            with_hint(models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle').\
            filter(or_(*chunk))
        for scope, name, did_type in query:
            if did_type == DIDType.DATASET:
                messages.append({'event_type': 'ERASE',
                                 'payload': dumps({'scope': scope.external,
                                                   'name': name,
                                                   'account': 'root'})})
            deleted_rules.append(and_(models.ReplicationRule.scope == scope,
                                      models.ReplicationRule.name == name))
            deleted_dids.append(and_(models.DataIdentifier.scope == scope,
                                     models.DataIdentifier.name == name))
            if session.bind.dialect.name == 'oracle':
                oracle_version = int(session.connection().connection.version.split('.')[0])
                if oracle_version >= 12:
                    deleted_did_meta.append(and_(models.DidMeta.scope == scope,
                                                 models.DidMeta.name == name))
            else:
                deleted_did_meta.append(and_(models.DidMeta.scope == scope,
                                             models.DidMeta.name == name))

    # Remove Archive Constituents
    removed_constituents = []
    constituents_to_delete_condition = []
    for chunk in chunks(archive_contents_condition, 30):
        query = session.query(models.ConstituentAssociation). \
            with_hint(models.ConstituentAssociation, "INDEX(ARCHIVE_CONTENTS ARCH_CONTENTS_CHILD_IDX)", 'oracle'). \
            filter(or_(*chunk))
        for constituent in query:
            removed_constituents.append({'scope': constituent.child_scope, 'name': constituent.child_name})
            constituents_to_delete_condition.append(
                and_(models.ConstituentAssociation.scope == constituent.scope,
                     models.ConstituentAssociation.name == constituent.name,
                     models.ConstituentAssociation.child_scope == constituent.child_scope,
                     models.ConstituentAssociation.child_name == constituent.child_name))

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

            if len(constituents_to_delete_condition) > 200:
                session.query(models.ConstituentAssociation).\
                    with_hint(models.ConstituentAssociation, "INDEX(ARCHIVE_CONTENTS ARCH_CONTENTS_PK)", 'oracle').\
                    filter(or_(*constituents_to_delete_condition)).\
                    delete(synchronize_session=False)
                constituents_to_delete_condition.clear()

                __cleanup_after_replica_deletion(rse_id=rse_id, files=removed_constituents, session=session)
                removed_constituents.clear()
    if constituents_to_delete_condition:
        session.query(models.ConstituentAssociation). \
            with_hint(models.ConstituentAssociation, "INDEX(ARCHIVE_CONTENTS ARCH_CONTENTS_PK)", 'oracle'). \
            filter(or_(*constituents_to_delete_condition)). \
            delete(synchronize_session=False)
        __cleanup_after_replica_deletion(rse_id=rse_id, files=removed_constituents, session=session)

    # Remove rules in Waiting for approval or Suspended
    for chunk in chunks(deleted_rules, 100):
        session.query(models.ReplicationRule).\
            with_hint(models.ReplicationRule, "INDEX(RULES RULES_SCOPE_NAME_IDX)", 'oracle').\
            filter(or_(*chunk)).\
            filter(models.ReplicationRule.state.in_((RuleState.SUSPENDED,
                                                     RuleState.WAITING_APPROVAL))).\
            delete(synchronize_session=False)

    # Remove DID Metadata
    for chunk in chunks(deleted_did_meta, 100):
        session.query(models.DidMeta).\
            filter(or_(*chunk)).\
            delete(synchronize_session=False)

    for chunk in chunks(messages, 100):
        session.bulk_insert_mappings(models.Message, chunk)

    for chunk in chunks(deleted_dids, 100):
        session.query(models.DataIdentifier).\
            with_hint(models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle').\
            filter(or_(*chunk)).\
            delete(synchronize_session=False)
        if session.bind.dialect.name != 'oracle':
            rucio.core.did.insert_deleted_dids(chunk, session=session)

    # Set is_archive = false on collections which don't have archive children anymore
    for chunk in chunks(clt_is_not_archive_condition, 100):
        clt_to_update = list(session
                             .query(models.DataIdentifierAssociation.scope,
                                    models.DataIdentifierAssociation.name)
                             .distinct(models.DataIdentifierAssociation.scope,
                                       models.DataIdentifierAssociation.name)
                             .with_hint(models.DataIdentifierAssociation, "INDEX(CONTENTS CONTENTS_PK)", 'oracle')
                             .filter(or_(*chunk)))
        if clt_to_update:
            session.query(models.DataIdentifier).\
                with_hint(models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle').\
                filter(or_(and_(models.DataIdentifier.scope == scope,
                                models.DataIdentifier.name == name,
                                models.DataIdentifier.is_archive == true())
                           for scope, name in clt_to_update)).\
                update({'is_archive': False}, synchronize_session=False)


@transactional_session
def get_replica(rse_id, scope, name, session=None):
    """
    Get File replica.

    :param rse_id: The RSE Id.
    :param scope: the scope name.
    :param name: The data identifier name.
    :param session: The database session in use.

    :returns: A dictionary with the list of replica attributes.
    """
    try:
        row = session.query(models.RSEFileAssociation).filter_by(rse_id=rse_id, scope=scope, name=name).one()
        result = {}
        for column in row.__table__.columns:
            result[column.name] = getattr(row, column.name)
        return result
    except NoResultFound:
        raise exception.ReplicaNotFound("No row found for scope: %s name: %s rse: %s" % (scope, name, get_rse_name(rse_id=rse_id, session=session)))


@transactional_session
def list_and_mark_unlocked_replicas(limit, bytes=None, rse_id=None, delay_seconds=600, only_delete_obsolete=False, session=None):
    """
    List RSE File replicas with no locks.

    :param limit:                    Number of replicas returned.
    :param bytes:                    The amount of needed bytes.
    :param rse_id:                   The rse_id.
    :param delay_seconds:            The delay to query replicas in BEING_DELETED state
    :param only_delete_obsolete      If set to True, will only return the replicas with EPOCH tombstone
    :param session:                  The database session in use.

    :returns: a list of dictionary replica.
    """

    none_value = None  # Hack to get pep8 happy...
    query = session.query(models.RSEFileAssociation.scope,
                          models.RSEFileAssociation.name,
                          models.RSEFileAssociation.path,
                          models.RSEFileAssociation.bytes,
                          models.RSEFileAssociation.tombstone,
                          models.RSEFileAssociation.state).\
        with_hint(models.RSEFileAssociation, "INDEX_RS_ASC(replicas REPLICAS_TOMBSTONE_IDX)  NO_INDEX_FFS(replicas REPLICAS_TOMBSTONE_IDX)", 'oracle').\
        filter(models.RSEFileAssociation.tombstone < datetime.utcnow()).\
        filter(models.RSEFileAssociation.lock_cnt == 0).\
        filter(case([(models.RSEFileAssociation.tombstone != none_value, models.RSEFileAssociation.rse_id), ]) == rse_id).\
        filter(or_(models.RSEFileAssociation.state.in_((ReplicaState.AVAILABLE, ReplicaState.UNAVAILABLE, ReplicaState.BAD)),
                   and_(models.RSEFileAssociation.state == ReplicaState.BEING_DELETED, models.RSEFileAssociation.updated_at < datetime.utcnow() - timedelta(seconds=delay_seconds)))).\
        filter(~exists(select([1]).prefix_with("/*+ INDEX(SOURCES SOURCES_SC_NM_DST_IDX) */", dialect='oracle')
                       .where(and_(models.RSEFileAssociation.scope == models.Source.scope,
                                   models.RSEFileAssociation.name == models.Source.name,
                                   models.RSEFileAssociation.rse_id == models.Source.rse_id)))).\
        with_for_update(skip_locked=True).\
        order_by(models.RSEFileAssociation.tombstone)

    needed_space = bytes
    total_bytes, total_files = 0, 0
    rows = []
    replica_clause = []
    for (scope, name, path, bytes, tombstone, state) in query.yield_per(1000):
        # Check if more than one replica is available
        replica_cnt = session.query(func.count(models.RSEFileAssociation.scope)).\
            with_hint(models.RSEFileAssociation, "index(REPLICAS REPLICAS_PK)", 'oracle').\
            filter(and_(models.RSEFileAssociation.scope == scope, models.RSEFileAssociation.name == name, models.RSEFileAssociation.rse_id != rse_id)).one()

        if replica_cnt[0] > 1:
            if state != ReplicaState.UNAVAILABLE:
                if tombstone != OBSOLETE:
                    if only_delete_obsolete:
                        break
                    if needed_space is not None and total_bytes > needed_space:
                        break
                total_bytes += bytes

                total_files += 1
                if total_files > limit:
                    break

            rows.append({'scope': scope, 'name': name, 'path': path,
                         'bytes': bytes, 'tombstone': tombstone,
                         'state': state})
            replica_clause.append(and_(models.RSEFileAssociation.scope == scope,
                                       models.RSEFileAssociation.name == name,
                                       models.RSEFileAssociation.rse_id == rse_id))
        else:
            # If this is the last replica, check if there are some requests
            request_cnt = session.query(func.count()).\
                with_hint(models.Request, "INDEX(requests REQUESTS_SCOPE_NAME_RSE_IDX)", 'oracle').\
                filter(and_(models.Request.scope == scope,
                            models.Request.name == name)).one()

            if request_cnt[0] == 0:
                if tombstone != OBSOLETE:
                    if only_delete_obsolete:
                        break
                    if needed_space is not None and total_bytes > needed_space:
                        break
                total_bytes += bytes

                total_files += 1
                if total_files > limit:
                    break

                rows.append({'scope': scope, 'name': name, 'path': path,
                             'bytes': bytes, 'tombstone': tombstone,
                             'state': state})

                replica_clause.append(and_(models.RSEFileAssociation.scope == scope,
                                           models.RSEFileAssociation.name == name,
                                           models.RSEFileAssociation.rse_id == rse_id))
    for chunk in chunks(replica_clause, 100):
        session.query(models.RSEFileAssociation).filter(or_(*chunk)).\
            with_hint(models.RSEFileAssociation, text="INDEX(REPLICAS REPLICAS_PK)", dialect_name='oracle').\
            update({'updated_at': datetime.utcnow(), 'state': ReplicaState.BEING_DELETED, 'tombstone': datetime(1970, 1, 1)}, synchronize_session=False)

    return rows


@transactional_session
def update_replicas_states(replicas, nowait=False, session=None):
    """
    Update File replica information and state.

    :param replicas:        The list of replicas.
    :param nowait:          Nowait parameter for the for_update queries.
    :param session:         The database session in use.
    """

    for replica in replicas:
        query = session.query(models.RSEFileAssociation).filter_by(rse_id=replica['rse_id'], scope=replica['scope'], name=replica['name'])
        try:
            if nowait:
                query.with_for_update(nowait=True).one()
        except NoResultFound:
            # remember scope, name and rse
            raise exception.ReplicaNotFound("No row found for scope: %s name: %s rse: %s" % (replica['scope'], replica['name'], get_rse_name(replica['rse_id'], session=session)))

        if isinstance(replica['state'], string_types):
            replica['state'] = ReplicaState(replica['state'])

        values = {'state': replica['state']}
        if replica['state'] == ReplicaState.BEING_DELETED:
            query = query.filter_by(lock_cnt=0)
            # Exclude replicas use as sources
            stmt = exists([1]).where(and_(models.RSEFileAssociation.scope == models.Source.scope,
                                          models.RSEFileAssociation.name == models.Source.name,
                                          models.RSEFileAssociation.rse_id == models.Source.rse_id))
            query = query.filter(not_(stmt))
            values['tombstone'] = OBSOLETE
        elif replica['state'] == ReplicaState.AVAILABLE:
            rucio.core.lock.successful_transfer(scope=replica['scope'], name=replica['name'], rse_id=replica['rse_id'], nowait=nowait, session=session)
        elif replica['state'] == ReplicaState.UNAVAILABLE:
            rucio.core.lock.failed_transfer(scope=replica['scope'], name=replica['name'], rse_id=replica['rse_id'],
                                            error_message=replica.get('error_message', None),
                                            broken_rule_id=replica.get('broken_rule_id', None),
                                            broken_message=replica.get('broken_message', None),
                                            nowait=nowait, session=session)
        elif replica['state'] == ReplicaState.TEMPORARY_UNAVAILABLE:
            query = query.filter(or_(models.RSEFileAssociation.state == ReplicaState.AVAILABLE, models.RSEFileAssociation.state == ReplicaState.TEMPORARY_UNAVAILABLE))

        if 'path' in replica and replica['path']:
            values['path'] = replica['path']

        if not query.update(values, synchronize_session=False):
            if 'rse' not in replica:
                replica['rse'] = get_rse_name(rse_id=replica['rse_id'], session=session)
            raise exception.UnsupportedOperation('State %(state)s for replica %(scope)s:%(name)s on %(rse)s cannot be updated' % replica)
    return True


@transactional_session
def touch_replica(replica, session=None):
    """
    Update the accessed_at timestamp of the given file replica/did but don't wait if row is locked.

    :param replica: a dictionary with the information of the affected replica.
    :param session: The database session in use.

    :returns: True, if successful, False otherwise.
    """
    try:
        accessed_at, none_value = replica.get('accessed_at') or datetime.utcnow(), None

        session.query(models.RSEFileAssociation).\
            filter_by(rse_id=replica['rse_id'], scope=replica['scope'], name=replica['name']).\
            with_hint(models.RSEFileAssociation, "index(REPLICAS REPLICAS_PK)", 'oracle').\
            with_for_update(nowait=True).one()

        session.query(models.RSEFileAssociation).filter_by(rse_id=replica['rse_id'], scope=replica['scope'], name=replica['name']).\
            with_hint(models.RSEFileAssociation, "index(REPLICAS REPLICAS_PK)", 'oracle').\
            update({'accessed_at': accessed_at,
                    'tombstone': case([(and_(models.RSEFileAssociation.tombstone != none_value,
                                             models.RSEFileAssociation.tombstone != OBSOLETE),
                                        accessed_at)],
                                      else_=models.RSEFileAssociation.tombstone)},
                   synchronize_session=False)

        session.query(models.DataIdentifier).\
            filter_by(scope=replica['scope'], name=replica['name'], did_type=DIDType.FILE).\
            with_hint(models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle').\
            with_for_update(nowait=True).one()

        session.query(models.DataIdentifier).\
            filter_by(scope=replica['scope'], name=replica['name'], did_type=DIDType.FILE).\
            with_hint(models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle').\
            update({'accessed_at': accessed_at}, synchronize_session=False)

    except DatabaseError:
        return False
    except NoResultFound:
        return True

    return True


@transactional_session
def update_replica_state(rse_id, scope, name, state, session=None):
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
def get_and_lock_file_replicas(scope, name, nowait=False, restrict_rses=None, session=None):
    """
    Get file replicas for a specific scope:name.

    :param scope:          The scope of the did.
    :param name:           The name of the did.
    :param nowait:         Nowait parameter for the FOR UPDATE statement
    :param restrict_rses:  Possible RSE_ids to filter on.
    :param session:        The db session in use.
    :returns:              List of SQLAlchemy Replica Objects
    """

    query = session.query(models.RSEFileAssociation).filter_by(scope=scope, name=name).filter(models.RSEFileAssociation.state != ReplicaState.BEING_DELETED)
    if restrict_rses is not None:
        if len(restrict_rses) < 10:
            rse_clause = []
            for rse_id in restrict_rses:
                rse_clause.append(models.RSEFileAssociation.rse_id == rse_id)
            if rse_clause:
                query = query.filter(or_(*rse_clause))
    return query.with_for_update(nowait=nowait).all()


@transactional_session
def get_source_replicas(scope, name, source_rses=None, session=None):
    """
    Get soruce replicas for a specific scope:name.

    :param scope:          The scope of the did.
    :param name:           The name of the did.
    :param soruce_rses:    Possible RSE_ids to filter on.
    :param session:        The db session in use.
    :returns:              List of SQLAlchemy Replica Objects
    """

    query = session.query(models.RSEFileAssociation.rse_id).filter_by(scope=scope, name=name).filter(models.RSEFileAssociation.state == ReplicaState.AVAILABLE)
    if source_rses:
        if len(source_rses) < 10:
            rse_clause = []
            for rse_id in source_rses:
                rse_clause.append(models.RSEFileAssociation.rse_id == rse_id)
            if rse_clause:
                query = query.filter(or_(*rse_clause))
    return [a[0] for a in query.all()]


@transactional_session
def get_and_lock_file_replicas_for_dataset(scope, name, nowait=False, restrict_rses=None,
                                           total_threads=None, thread_id=None,
                                           session=None):
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
    if session.bind.dialect.name == 'postgresql':
        # Get content
        content_query = session.query(models.DataIdentifierAssociation.child_scope,
                                      models.DataIdentifierAssociation.child_name,
                                      models.DataIdentifierAssociation.bytes,
                                      models.DataIdentifierAssociation.md5,
                                      models.DataIdentifierAssociation.adler32).\
            with_hint(models.DataIdentifierAssociation,
                      "INDEX_RS_ASC(CONTENTS CONTENTS_PK) NO_INDEX_FFS(CONTENTS CONTENTS_PK)",
                      'oracle').\
            filter(models.DataIdentifierAssociation.scope == scope,
                   models.DataIdentifierAssociation.name == name)

        if total_threads and total_threads > 1:
            content_query = filter_thread_work(session=session, query=content_query, total_threads=total_threads,
                                               thread_id=thread_id, hash_variable='child_name')

        for child_scope, child_name, bytes, md5, adler32 in content_query.yield_per(1000):
            files[(child_scope, child_name)] = {'scope': child_scope,
                                                'name': child_name,
                                                'bytes': bytes,
                                                'md5': md5,
                                                'adler32': adler32}
            replicas[(child_scope, child_name)] = []

        # Get replicas and lock them
        query = session.query(models.DataIdentifierAssociation.child_scope,
                              models.DataIdentifierAssociation.child_name,
                              models.DataIdentifierAssociation.bytes,
                              models.DataIdentifierAssociation.md5,
                              models.DataIdentifierAssociation.adler32,
                              models.RSEFileAssociation)\
            .with_hint(models.DataIdentifierAssociation,
                       "INDEX_RS_ASC(CONTENTS CONTENTS_PK) NO_INDEX_FFS(CONTENTS CONTENTS_PK)",
                       'oracle')\
            .filter(and_(models.DataIdentifierAssociation.child_scope == models.RSEFileAssociation.scope,
                         models.DataIdentifierAssociation.child_name == models.RSEFileAssociation.name,
                         models.RSEFileAssociation.state != ReplicaState.BEING_DELETED))\
            .filter(models.DataIdentifierAssociation.scope == scope,
                    models.DataIdentifierAssociation.name == name)

        if restrict_rses is not None:
            if len(restrict_rses) < 10:
                rse_clause = []
                for rse_id in restrict_rses:
                    rse_clause.append(models.RSEFileAssociation.rse_id == rse_id)
                if rse_clause:
                    query = session.query(models.DataIdentifierAssociation.child_scope,
                                          models.DataIdentifierAssociation.child_name,
                                          models.DataIdentifierAssociation.bytes,
                                          models.DataIdentifierAssociation.md5,
                                          models.DataIdentifierAssociation.adler32,
                                          models.RSEFileAssociation)\
                                   .with_hint(models.DataIdentifierAssociation,
                                              "INDEX_RS_ASC(CONTENTS CONTENTS_PK) NO_INDEX_FFS(CONTENTS CONTENTS_PK)",
                                              'oracle')\
                                   .filter(and_(models.DataIdentifierAssociation.child_scope == models.RSEFileAssociation.scope,
                                                models.DataIdentifierAssociation.child_name == models.RSEFileAssociation.name,
                                                models.RSEFileAssociation.state != ReplicaState.BEING_DELETED,
                                                or_(*rse_clause)))\
                                   .filter(models.DataIdentifierAssociation.scope == scope,
                                           models.DataIdentifierAssociation.name == name)

    else:
        query = session.query(models.DataIdentifierAssociation.child_scope,
                              models.DataIdentifierAssociation.child_name,
                              models.DataIdentifierAssociation.bytes,
                              models.DataIdentifierAssociation.md5,
                              models.DataIdentifierAssociation.adler32,
                              models.RSEFileAssociation)\
            .with_hint(models.DataIdentifierAssociation,
                       "INDEX_RS_ASC(CONTENTS CONTENTS_PK) NO_INDEX_FFS(CONTENTS CONTENTS_PK)",
                       'oracle') \
            .with_hint(models.RSEFileAssociation, "INDEX(REPLICAS REPLICAS_PK)", 'oracle')\
            .outerjoin(models.RSEFileAssociation,
                       and_(models.DataIdentifierAssociation.child_scope == models.RSEFileAssociation.scope,
                            models.DataIdentifierAssociation.child_name == models.RSEFileAssociation.name,
                            models.RSEFileAssociation.state != ReplicaState.BEING_DELETED)).\
            filter(models.DataIdentifierAssociation.scope == scope,
                   models.DataIdentifierAssociation.name == name)

        if restrict_rses is not None:
            if len(restrict_rses) < 10:
                rse_clause = []
                for rse_id in restrict_rses:
                    rse_clause.append(models.RSEFileAssociation.rse_id == rse_id)
                if rse_clause:
                    query = session.query(models.DataIdentifierAssociation.child_scope,
                                          models.DataIdentifierAssociation.child_name,
                                          models.DataIdentifierAssociation.bytes,
                                          models.DataIdentifierAssociation.md5,
                                          models.DataIdentifierAssociation.adler32,
                                          models.RSEFileAssociation)\
                                   .with_hint(models.DataIdentifierAssociation,
                                              "INDEX_RS_ASC(CONTENTS CONTENTS_PK) NO_INDEX_FFS(CONTENTS CONTENTS_PK)",
                                              'oracle')\
                                   .outerjoin(models.RSEFileAssociation,
                                              and_(models.DataIdentifierAssociation.child_scope == models.RSEFileAssociation.scope,
                                                   models.DataIdentifierAssociation.child_name == models.RSEFileAssociation.name,
                                                   models.RSEFileAssociation.state != ReplicaState.BEING_DELETED,
                                                   or_(*rse_clause)))\
                                   .filter(models.DataIdentifierAssociation.scope == scope,
                                           models.DataIdentifierAssociation.name == name)

    if total_threads and total_threads > 1:
        query = filter_thread_work(session=session, query=query, total_threads=total_threads,
                                   thread_id=thread_id, hash_variable='child_name')

    query = query.with_for_update(nowait=nowait, of=models.RSEFileAssociation.lock_cnt)

    for child_scope, child_name, bytes, md5, adler32, replica in query.yield_per(1000):
        if (child_scope, child_name) not in files:
            files[(child_scope, child_name)] = {'scope': child_scope,
                                                'name': child_name,
                                                'bytes': bytes,
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
                                    session=None):
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
    query = session.query(models.DataIdentifierAssociation.child_scope,
                          models.DataIdentifierAssociation.child_name,
                          models.RSEFileAssociation.rse_id)\
        .with_hint(models.DataIdentifierAssociation, "INDEX_RS_ASC(CONTENTS CONTENTS_PK) NO_INDEX_FFS(CONTENTS CONTENTS_PK)", 'oracle')\
        .outerjoin(models.RSEFileAssociation,
                   and_(models.DataIdentifierAssociation.child_scope == models.RSEFileAssociation.scope,
                        models.DataIdentifierAssociation.child_name == models.RSEFileAssociation.name,
                        models.RSEFileAssociation.state == ReplicaState.AVAILABLE)).\
        filter(models.DataIdentifierAssociation.scope == scope, models.DataIdentifierAssociation.name == name)

    if source_rses:
        if len(source_rses) < 10:
            rse_clause = []
            for rse_id in source_rses:
                rse_clause.append(models.RSEFileAssociation.rse_id == rse_id)
            if rse_clause:
                query = session.query(models.DataIdentifierAssociation.child_scope,
                                      models.DataIdentifierAssociation.child_name,
                                      models.RSEFileAssociation.rse_id)\
                               .with_hint(models.DataIdentifierAssociation, "INDEX_RS_ASC(CONTENTS CONTENTS_PK) NO_INDEX_FFS(CONTENTS CONTENTS_PK)", 'oracle')\
                               .outerjoin(models.RSEFileAssociation,
                                          and_(models.DataIdentifierAssociation.child_scope == models.RSEFileAssociation.scope,
                                               models.DataIdentifierAssociation.child_name == models.RSEFileAssociation.name,
                                               models.RSEFileAssociation.state == ReplicaState.AVAILABLE,
                                               or_(*rse_clause)))\
                               .filter(models.DataIdentifierAssociation.scope == scope,
                                       models.DataIdentifierAssociation.name == name)

    if total_threads and total_threads > 1:
        query = filter_thread_work(session=session, query=query, total_threads=total_threads,
                                   thread_id=thread_id, hash_variable='child_name')

    replicas = {}

    for child_scope, child_name, rse_id in query:

        if (child_scope, child_name) in replicas:
            if rse_id:
                replicas[(child_scope, child_name)].append(rse_id)
        else:
            replicas[(child_scope, child_name)] = []
            if rse_id:
                replicas[(child_scope, child_name)].append(rse_id)

    return replicas


@read_session
def get_replica_atime(replica, session=None):
    """
    Get the accessed_at timestamp for a replica. Just for testing.
    :param replicas: List of dictionaries {scope, name, rse_id, path}
    :param session: Database session to use.

    :returns: A datetime timestamp with the last access time.
    """
    return session.query(models.RSEFileAssociation.accessed_at).filter_by(scope=replica['scope'], name=replica['name'], rse_id=replica['rse_id']).\
        with_hint(models.RSEFileAssociation, text="INDEX(REPLICAS REPLICAS_PK)", dialect_name='oracle').one()[0]


@transactional_session
def touch_collection_replicas(collection_replicas, session=None):
    """
    Update the accessed_at timestamp of the given collection replicas.

    :param collection_replicas: the list of collection replicas.
    :param session: The database session in use.

    :returns: True, if successful, False otherwise.
    """

    now = datetime.utcnow()
    for collection_replica in collection_replicas:
        try:
            session.query(models.CollectionReplica).filter_by(scope=collection_replica['scope'], name=collection_replica['name'], rse_id=collection_replica['rse_id']).\
                update({'accessed_at': collection_replica.get('accessed_at') or now}, synchronize_session=False)
        except DatabaseError:
            return False

    return True


@stream_session
def list_dataset_replicas(scope, name, deep=False, session=None):
    """
    :param scope: The scope of the dataset.
    :param name: The name of the dataset.
    :param deep: Lookup at the file level.
    :param session: Database session to use.

    :returns: A list of dictionaries containing the dataset replicas
              with associated metrics and timestamps
    """

    if not deep:
        query = session.query(models.CollectionReplica.scope,
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
                              models.CollectionReplica.accessed_at)\
            .filter_by(scope=scope, name=name, did_type=DIDType.DATASET)\
            .filter(models.CollectionReplica.rse_id == models.RSE.id)\
            .filter(models.RSE.deleted == false())

        for row in query:
            yield row._asdict()

    else:

        # find maximum values
        content_query = session\
            .query(func.sum(models.DataIdentifierAssociation.bytes).label("bytes"),
                   func.count().label("length"))\
            .with_hint(models.DataIdentifierAssociation, "INDEX_RS_ASC(CONTENTS CONTENTS_PK) NO_INDEX_FFS(CONTENTS CONTENTS_PK)", 'oracle')\
            .filter(models.DataIdentifierAssociation.scope == scope)\
            .filter(models.DataIdentifierAssociation.name == name)

        bytes, length = 0, 0
        for row in content_query:
            bytes, length = row.bytes, row.length

        # find archives that contain files of the requested dataset
        sub_query_archives = session\
            .query(models.DataIdentifierAssociation.scope.label('dataset_scope'),
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
                   models.RSEFileAssociation.updated_at)\
            .filter(models.DataIdentifierAssociation.scope == scope)\
            .filter(models.DataIdentifierAssociation.name == name)\
            .filter(models.ConstituentAssociation.child_scope == models.DataIdentifierAssociation.child_scope)\
            .filter(models.ConstituentAssociation.child_name == models.DataIdentifierAssociation.child_name)\
            .filter(models.ConstituentAssociation.scope == models.RSEFileAssociation.scope)\
            .filter(models.ConstituentAssociation.name == models.RSEFileAssociation.name)\
            .filter(models.RSEFileAssociation.rse_id == models.RSE.id)\
            .filter(models.RSEFileAssociation.state == ReplicaState.AVAILABLE)\
            .filter(models.RSE.deleted == false())\
            .subquery()

        # count the metrics
        group_query_archives = session\
            .query(sub_query_archives.c.dataset_scope,
                   sub_query_archives.c.dataset_name,
                   sub_query_archives.c.file_scope,
                   sub_query_archives.c.file_name,
                   sub_query_archives.c.rse_id,
                   sub_query_archives.c.rse,
                   func.sum(sub_query_archives.c.file_bytes).label('file_bytes'),
                   func.min(sub_query_archives.c.created_at).label('created_at'),
                   func.max(sub_query_archives.c.updated_at).label('updated_at'),
                   func.max(sub_query_archives.c.accessed_at).label('accessed_at'))\
            .group_by(sub_query_archives.c.dataset_scope,
                      sub_query_archives.c.dataset_name,
                      sub_query_archives.c.file_scope,
                      sub_query_archives.c.file_name,
                      sub_query_archives.c.rse_id,
                      sub_query_archives.c.rse)\
            .subquery()

        # bring it in the same column state as the non-archive query
        full_query_archives = session\
            .query(group_query_archives.c.dataset_scope.label('scope'),
                   group_query_archives.c.dataset_name.label('name'),
                   group_query_archives.c.rse_id,
                   group_query_archives.c.rse,
                   func.sum(group_query_archives.c.file_bytes).label('available_bytes'),
                   func.count().label('available_length'),
                   func.min(group_query_archives.c.created_at).label('created_at'),
                   func.max(group_query_archives.c.updated_at).label('updated_at'),
                   func.max(group_query_archives.c.accessed_at).label('accessed_at'))\
            .group_by(group_query_archives.c.dataset_scope,
                      group_query_archives.c.dataset_name,
                      group_query_archives.c.rse_id,
                      group_query_archives.c.rse)

        # find the non-archive dataset replicas
        sub_query = session\
            .query(models.DataIdentifierAssociation.scope,
                   models.DataIdentifierAssociation.name,
                   models.RSEFileAssociation.rse_id,
                   func.sum(models.RSEFileAssociation.bytes).label("available_bytes"),
                   func.count().label("available_length"),
                   func.min(models.RSEFileAssociation.created_at).label("created_at"),
                   func.max(models.RSEFileAssociation.updated_at).label("updated_at"),
                   func.max(models.RSEFileAssociation.accessed_at).label("accessed_at"))\
            .with_hint(models.DataIdentifierAssociation, "INDEX_RS_ASC(CONTENTS CONTENTS_PK) INDEX_RS_ASC(REPLICAS REPLICAS_PK) NO_INDEX_FFS(CONTENTS CONTENTS_PK)", 'oracle')\
            .filter(models.DataIdentifierAssociation.child_scope == models.RSEFileAssociation.scope)\
            .filter(models.DataIdentifierAssociation.child_name == models.RSEFileAssociation.name)\
            .filter(models.DataIdentifierAssociation.scope == scope)\
            .filter(models.DataIdentifierAssociation.name == name)\
            .filter(models.RSEFileAssociation.state == ReplicaState.AVAILABLE)\
            .group_by(models.DataIdentifierAssociation.scope,
                      models.DataIdentifierAssociation.name,
                      models.RSEFileAssociation.rse_id)\
            .subquery()

        query = session\
            .query(sub_query.c.scope,
                   sub_query.c.name,
                   sub_query.c.rse_id,
                   models.RSE.rse,
                   sub_query.c.available_bytes,
                   sub_query.c.available_length,
                   sub_query.c.created_at,
                   sub_query.c.updated_at,
                   sub_query.c.accessed_at)\
            .filter(models.RSE.id == sub_query.c.rse_id)\
            .filter(models.RSE.deleted == false())

        # join everything together
        final_query = query.union_all(full_query_archives)

        for row in final_query.all():
            replica = row._asdict()
            replica['length'], replica['bytes'] = length, bytes
            if replica['length'] == row.available_length:
                replica['state'] = ReplicaState.AVAILABLE
            else:
                replica['state'] = ReplicaState.UNAVAILABLE
            yield replica


@stream_session
def list_dataset_replicas_bulk(names_by_intscope, session=None):
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
            query = session.query(models.CollectionReplica.scope,
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
                                  models.CollectionReplica.accessed_at) \
                .filter(models.CollectionReplica.did_type == DIDType.DATASET) \
                .filter(models.CollectionReplica.rse_id == models.RSE.id) \
                .filter(or_(*chunk)) \
                .filter(models.RSE.deleted == false())
            for row in query:
                yield row._asdict()
    except NoResultFound:
        raise exception.DataIdentifierNotFound('No Data Identifiers found')


@stream_session
def list_dataset_replicas_vp(scope, name, deep=False, session=None, logger=logging.log):
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
def list_datasets_per_rse(rse_id, filters=None, limit=None, session=None):
    """
    List datasets at a RSE.

    :param rse: the rse id.
    :param filters: dictionary of attributes by which the results should be filtered.
    :param limit: limit number.
    :param session: Database session to use.

    :returns: A list of dict dataset replicas
    """
    query = session.query(models.CollectionReplica.scope,
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
                          models.CollectionReplica.accessed_at)\
        .filter_by(did_type=DIDType.DATASET)\
        .filter(models.CollectionReplica.rse_id == models.RSE.id)\
        .filter(models.RSE.id == rse_id)\
        .filter(models.RSE.deleted == false())

    for (k, v) in filters and filters.items() or []:
        if k == 'name' or k == 'scope':
            v_str = v if k != 'scope' else v.internal
            if '*' in v_str or '%' in v_str:
                if session.bind.dialect.name == 'postgresql':  # PostgreSQL escapes automatically
                    query = query.filter(getattr(models.CollectionReplica, k).like(v_str.replace('*', '%')))
                else:
                    query = query.filter(getattr(models.CollectionReplica, k).like(v_str.replace('*', '%'), escape='\\'))
            else:
                query = query.filter(getattr(models.CollectionReplica, k) == v)
                # hints ?
        elif k == 'created_before':
            created_before = str_to_date(v)
            query = query.filter(models.CollectionReplica.created_at <= created_before)
        elif k == 'created_after':
            created_after = str_to_date(v)
            query = query.filter(models.CollectionReplica.created_at >= created_after)
        else:
            query = query.filter(getattr(models.CollectionReplica, k) == v)

    if limit:
        query = query.limit(limit)

    for row in query:
        yield row._asdict()


@transactional_session
def get_cleaned_updated_collection_replicas(total_workers, worker_number, limit=None, session=None):
    """
    Get update request for collection replicas.
    :param total_workers:      Number of total workers.
    :param worker_number:      id of the executing worker.
    :param limit:              Maximum numberws to return.
    :param session:            Database session in use.
    :returns:                  List of update requests for collection replicas.
    """

    # Delete update requests which do not have collection_replicas
    session.query(models.UpdatedCollectionReplica).filter(models.UpdatedCollectionReplica.rse_id.is_(None)
                                                          & ~exists().where(and_(models.CollectionReplica.name == models.UpdatedCollectionReplica.name,  # NOQA: W503
                                                                                 models.CollectionReplica.scope == models.UpdatedCollectionReplica.scope))).delete(synchronize_session=False)
    session.query(models.UpdatedCollectionReplica).filter(models.UpdatedCollectionReplica.rse_id.isnot(None)
                                                          & ~exists().where(and_(models.CollectionReplica.name == models.UpdatedCollectionReplica.name,  # NOQA: W503
                                                                                 models.CollectionReplica.scope == models.UpdatedCollectionReplica.scope,
                                                                                 models.CollectionReplica.rse_id == models.UpdatedCollectionReplica.rse_id))).delete(synchronize_session=False)

    # Delete duplicates
    if session.bind.dialect.name == 'oracle':
        schema = ''
        if BASE.metadata.schema:
            schema = BASE.metadata.schema + '.'
        session.execute('DELETE FROM {schema}updated_col_rep A WHERE A.rowid > ANY (SELECT B.rowid FROM {schema}updated_col_rep B WHERE A.scope = B.scope AND A.name=B.name AND A.did_type=B.did_type AND (A.rse_id=B.rse_id OR (A.rse_id IS NULL and B.rse_id IS NULL)))'.format(schema=schema))
    elif session.bind.dialect.name == 'mysql':
        subquery1 = session.query(func.max(models.UpdatedCollectionReplica.id).label('max_id')).\
            group_by(models.UpdatedCollectionReplica.scope,
                     models.UpdatedCollectionReplica.name,
                     models.UpdatedCollectionReplica.rse_id).subquery()
        subquery2 = session.query(subquery1.c.max_id).subquery()
        session.query(models.UpdatedCollectionReplica).filter(models.UpdatedCollectionReplica.id.notin_(subquery2)).delete(synchronize_session=False)
    else:
        replica_update_requests = session.query(models.UpdatedCollectionReplica)
        update_requests_with_rse_id = []
        update_requests_without_rse_id = []
        duplicate_request_ids = []
        for update_request in replica_update_requests.all():
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
            session.query(models.UpdatedCollectionReplica).filter(models.UpdatedCollectionReplica.id.in_(chunk)).delete(synchronize_session=False)

    query = session.query(models.UpdatedCollectionReplica)
    if limit:
        query = query.limit(limit)
    return [update_request.to_dict() for update_request in query.all()]


@transactional_session
def update_collection_replica(update_request, session=None):
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
            collection_replica = session.query(models.CollectionReplica)\
                                        .filter_by(scope=update_request['scope'],
                                                   name=update_request['name'],
                                                   rse_id=update_request['rse_id'])\
                                        .one()
            ds_length = collection_replica.length
            old_available_replicas = collection_replica.available_replicas_cnt
            ds_bytes = collection_replica.bytes
        except NoResultFound:
            pass

        try:
            file_replica = session.query(models.RSEFileAssociation, models.DataIdentifierAssociation)\
                                  .filter(models.RSEFileAssociation.scope == models.DataIdentifierAssociation.child_scope,
                                          models.RSEFileAssociation.name == models.DataIdentifierAssociation.child_name,
                                          models.DataIdentifierAssociation.name == update_request['name'],
                                          models.RSEFileAssociation.rse_id == update_request['rse_id'],
                                          models.RSEFileAssociation.state == ReplicaState.AVAILABLE,
                                          update_request['scope'] == models.DataIdentifierAssociation.scope)\
                                  .with_entities(label('ds_available_bytes', func.sum(models.RSEFileAssociation.bytes)),
                                                 label('available_replicas', func.count()))\
                                  .one()
            available_replicas = file_replica.available_replicas
            ds_available_bytes = file_replica.ds_available_bytes
        except NoResultFound:
            pass

        if available_replicas >= ds_length:
            ds_replica_state = ReplicaState.AVAILABLE
        else:
            ds_replica_state = ReplicaState.UNAVAILABLE

        if old_available_replicas > 0 and available_replicas == 0:
            session.query(models.CollectionReplica).filter_by(scope=update_request['scope'],
                                                              name=update_request['name'],
                                                              rse_id=update_request['rse_id'])\
                                                   .delete()
        else:
            updated_replica = session.query(models.CollectionReplica).filter_by(scope=update_request['scope'],
                                                                                name=update_request['name'],
                                                                                rse_id=update_request['rse_id'])\
                                                                     .one()
            updated_replica.state = ds_replica_state
            updated_replica.available_replicas_cnt = available_replicas
            updated_replica.length = ds_length
            updated_replica.bytes = ds_bytes
            updated_replica.available_bytes = ds_available_bytes
    else:
        # Check all dataset replicas
        association = session.query(models.DataIdentifierAssociation)\
                             .filter_by(scope=update_request['scope'],
                                        name=update_request['name'])\
                             .with_entities(label('ds_length', func.count()),
                                            label('ds_bytes', func.sum(models.DataIdentifierAssociation.bytes)))\
                             .one()
        ds_length = association.ds_length
        ds_bytes = association.ds_bytes
        ds_replica_state = None

        collection_replicas = session.query(models.CollectionReplica)\
                                     .filter_by(scope=update_request['scope'], name=update_request['name'])\
                                     .all()
        for collection_replica in collection_replicas:
            if ds_length:
                collection_replica.length = ds_length
            else:
                collection_replica.length = 0
            if ds_bytes:
                collection_replica.bytes = ds_bytes
            else:
                collection_replica.bytes = 0

        file_replicas = session.query(models.RSEFileAssociation, models.DataIdentifierAssociation)\
                               .filter(models.RSEFileAssociation.scope == models.DataIdentifierAssociation.child_scope,
                                       models.RSEFileAssociation.name == models.DataIdentifierAssociation.child_name,
                                       models.DataIdentifierAssociation.name == update_request['name'],
                                       models.RSEFileAssociation.state == ReplicaState.AVAILABLE,
                                       update_request['scope'] == models.DataIdentifierAssociation.scope)\
                               .with_entities(models.RSEFileAssociation.rse_id,
                                              label('ds_available_bytes', func.sum(models.RSEFileAssociation.bytes)),
                                              label('available_replicas', func.count()))\
                               .group_by(models.RSEFileAssociation.rse_id)\
                               .all()
        for file_replica in file_replicas:
            if file_replica.available_replicas >= ds_length:
                ds_replica_state = ReplicaState.AVAILABLE
            else:
                ds_replica_state = ReplicaState.UNAVAILABLE

            collection_replica = session.query(models.CollectionReplica)\
                                        .filter_by(scope=update_request['scope'], name=update_request['name'], rse_id=file_replica.rse_id)\
                                        .first()
            if collection_replica:
                collection_replica.state = ds_replica_state
                collection_replica.available_replicas_cnt = file_replica.available_replicas
                collection_replica.available_bytes = file_replica.ds_available_bytes
    session.query(models.UpdatedCollectionReplica).filter_by(id=update_request['id']).delete()


@read_session
def get_bad_pfns(limit=10000, thread=None, total_threads=None, session=None):
    """
    Returns a list of bad PFNs

    :param limit: The maximum number of replicas returned.
    :param thread: The assigned thread for this minos instance.
    :param total_threads: The total number of minos threads.
    :param session: The database session in use.

    returns: list of PFNs {'pfn': pfn, 'state': state, 'reason': reason, 'account': account, 'expires_at': expires_at}
    """
    result = []
    query = session.query(models.BadPFNs.path, models.BadPFNs.state, models.BadPFNs.reason, models.BadPFNs.account, models.BadPFNs.expires_at)
    query = filter_thread_work(session=session, query=query, total_threads=total_threads, thread_id=thread, hash_variable='path')
    query.order_by(models.BadPFNs.created_at)
    query = query.limit(limit)
    for path, state, reason, account, expires_at in query.yield_per(1000):
        result.append({'pfn': clean_surls([str(path)])[0], 'state': state, 'reason': reason, 'account': account, 'expires_at': expires_at})
    return result


@transactional_session
def bulk_add_bad_replicas(replicas, account, state=BadFilesStatus.TEMPORARY_UNAVAILABLE, reason=None, expires_at=None, session=None):
    """
    Bulk add new bad replicas.

    :param replicas: the list of bad replicas.
    :param account: The account who declared the bad replicas.
    :param state: The state of the file (SUSPICIOUS, BAD or TEMPORARY_UNAVAILABLE).
    :param session: The database session in use.

    :returns: True is successful.
    """
    for replica in replicas:
        insert_new_row = True
        if state == BadFilesStatus.TEMPORARY_UNAVAILABLE:
            query = session.query(models.BadReplicas).filter_by(scope=replica['scope'], name=replica['name'], rse_id=replica['rse_id'], state=state)
            if query.count():
                query.update({'state': BadFilesStatus.TEMPORARY_UNAVAILABLE, 'updated_at': datetime.utcnow(), 'account': account, 'reason': reason, 'expires_at': expires_at}, synchronize_session=False)
                insert_new_row = False
        if insert_new_row:
            new_bad_replica = models.BadReplicas(scope=replica['scope'], name=replica['name'], rse_id=replica['rse_id'], reason=reason,
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
def bulk_delete_bad_pfns(pfns, session=None):
    """
    Bulk delete bad PFNs.

    :param pfns: the list of new files.
    :param session: The database session in use.

    :returns: True is successful.
    """
    pfn_clause = []
    for pfn in pfns:
        pfn_clause.append(models.BadPFNs.path == pfn)

    for chunk in chunks(pfn_clause, 100):
        query = session.query(models.BadPFNs).filter(or_(*chunk))
        query.delete(synchronize_session=False)

    return True


@transactional_session
def bulk_delete_bad_replicas(bad_replicas, session=None):
    """
    Bulk delete bad replica.

    :param bad_replicas:    The list of bad replicas to delete (Dictionaries).
    :param session:         The database session in use.

    :returns: True is successful.
    """
    replica_clause = []
    for replica in bad_replicas:
        replica_clause.append(and_(models.BadReplicas.scope == replica['scope'],
                                   models.BadReplicas.name == replica['name'],
                                   models.BadReplicas.rse_id == replica['rse_id'],
                                   models.BadReplicas.state == replica['state']))

    for chunk in chunks(replica_clause, 100):
        session.query(models.BadReplicas).filter(or_(*chunk)).\
            delete(synchronize_session=False)
    return True


@transactional_session
def add_bad_pfns(pfns, account, state, reason=None, expires_at=None, session=None):
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

    if isinstance(state, string_types):
        rep_state = BadPFNStatus[state]
    else:
        rep_state = state

    pfns = clean_surls(pfns)
    for pfn in pfns:
        new_pfn = models.BadPFNs(path=str(pfn), account=account, state=rep_state, reason=reason, expires_at=expires_at)
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
def list_expired_temporary_unavailable_replicas(total_workers, worker_number, limit=10000, session=None):
    """
    List the expired temporary unavailable replicas

    :param total_workers:   Number of total workers.
    :param worker_number:   id of the executing worker.
    :param limit:           The maximum number of replicas returned.
    :param session:         The database session in use.
    """

    query = session.query(models.BadReplicas.scope, models.BadReplicas.name, models.BadReplicas.rse_id).\
        filter(models.BadReplicas.state == BadFilesStatus.TEMPORARY_UNAVAILABLE).\
        filter(models.BadReplicas.expires_at < datetime.utcnow()).\
        with_hint(models.ReplicationRule, "index(bad_replicas BAD_REPLICAS_EXPIRES_AT_IDX)", 'oracle').\
        order_by(models.BadReplicas.expires_at)

    query = filter_thread_work(session=session, query=query, total_threads=total_workers, thread_id=worker_number, hash_variable='name')
    query = query.limit(limit)
    return query.all()


@read_session
def get_replicas_state(scope=None, name=None, session=None):
    """
    Method used by the necromancer to get all the replicas of a DIDs
    :param scope: The scope of the file.
    :param name: The name of the file.
    :param session: The database session in use.

    :returns: A dictionary with the list of states as keys and the rse_ids as value
    """

    query = session.query(models.RSEFileAssociation.rse_id, models.RSEFileAssociation.state).filter_by(scope=scope, name=name)
    states = {}
    for res in query.all():
        rse_id, state = res
        if state not in states:
            states[state] = []
        states[state].append(rse_id)
    return states


@read_session
def get_suspicious_files(rse_expression, filter=None, **kwargs):
    """
    Gets a list of replicas from bad_replicas table which are: declared more than <nattempts> times since <younger_than> date,
    present on the RSE specified by the <rse_expression> and do not have a state in <exclude_states> list.
    Selected replicas can also be required to be <available_elsewhere> on another RSE than the one declared in bad_replicas table and/or
    be declared as <is_suspicious> in the bad_replicas table.
    Keyword Arguments:
    :param younger_than: Datetime object to select the replicas which were declared since younger_than date. Default value = 10 days ago.
    :param nattempts: The minimum number of replica appearances in the bad_replica DB table from younger_than date. Default value = 0.
    :param rse_expression: The RSE expression where the replicas are located.
    :param filter: Dictionary of attributes by which the RSE results should be filtered. e.g.: {'availability_write': True}
    :param: exclude_states: List of states which eliminates replicas from search result if any of the states in the list
                            was declared for a replica since younger_than date. Allowed values
                            = ['B', 'R', 'D', 'L', 'T', 'S'] (meaning 'BAD', 'RECOVERED', 'DELETED', 'LOST', 'TEMPORARY_UNAVAILABLE', 'SUSPICIOUS').
    :param: available_elsewhere: If True, only replicas declared in addition as AVAILABLE on another RSE
                                 than the one in the bad_replicas table will be taken into account. Default value = False.
    :param: is_suspicious: If True, only replicas declared as SUSPICIOUS in bad replicas table will be taken into account. Default value = False.
    :param session: The database session in use. Default value = None.

    :returns: a list of replicas:
    [{'scope': scope, 'name': name, 'rse': rse, 'rse_id': rse_id, cnt': cnt, 'created_at': created_at}, ...]
    """

    younger_than = kwargs.get("younger_than", datetime.now() - timedelta(days=10))
    nattempts = kwargs.get("nattempts", 0)
    session = kwargs.get("session", None)
    exclude_states = kwargs.get("exclude_states", ['B', 'R', 'D'])
    available_elsewhere = kwargs.get("available_elsewhere", False)
    is_suspicious = kwargs.get("is_suspicious", False)

    # only for the 2 web api used parameters, checking value types and assigning the default values
    if not isinstance(nattempts, int):
        nattempts = 0
    if not isinstance(younger_than, datetime):
        younger_than = datetime.now() - timedelta(days=10)

    # assembling exclude_states_clause
    exclude_states_clause = []
    for state in exclude_states:
        exclude_states_clause.append(BadFilesStatus(state))

    # making aliases for bad_replicas and replicas tables
    bad_replicas_alias = aliased(models.BadReplicas, name='bad_replicas_alias')
    replicas_alias = aliased(models.RSEFileAssociation, name='replicas_alias')

    # assembling the selection rse_clause
    rse_clause = []
    if rse_expression:
        parsedexp = parse_expression(expression=rse_expression, filter=filter, session=session)
        for rse in parsedexp:
            rse_clause.append(models.RSEFileAssociation.rse_id == rse['id'])

    # query base
    query = session.query(func.count(), bad_replicas_alias.scope, bad_replicas_alias.name, models.RSEFileAssociation.rse_id, func.min(models.RSEFileAssociation.created_at))\
                   .filter(models.RSEFileAssociation.rse_id == bad_replicas_alias.rse_id,
                           models.RSEFileAssociation.scope == bad_replicas_alias.scope,
                           models.RSEFileAssociation.name == bad_replicas_alias.name,
                           bad_replicas_alias.created_at >= younger_than)
    if is_suspicious:
        query.filter(bad_replicas_alias.state == BadFilesStatus.SUSPICIOUS)
    if rse_clause:
        query = query.filter(or_(*rse_clause))
    if available_elsewhere:
        available_replica = exists(select([1]).where(and_(replicas_alias.state == ReplicaState.AVAILABLE,
                                                          replicas_alias.scope == bad_replicas_alias.scope,
                                                          replicas_alias.name == bad_replicas_alias.name,
                                                          replicas_alias.rse_id != bad_replicas_alias.rse_id)))
        query = query.filter(available_replica)

    # it is required that the selected replicas
    # do not occur as BAD/DELETED/LOST/RECOVERED/...
    # in the bad_replicas table during the same time window.
    other_states_present = exists(select([1]).where(and_(models.BadReplicas.scope == bad_replicas_alias.scope,
                                                         models.BadReplicas.name == bad_replicas_alias.name,
                                                         models.BadReplicas.created_at >= younger_than,
                                                         models.BadReplicas.rse_id == bad_replicas_alias.rse_id,
                                                         models.BadReplicas.state.in_(exclude_states_clause))))
    query = query.filter(not_(other_states_present))

    # finally, the results are grouped by RSE, scope, name and required to have
    # at least 'nattempts' occurrences in the result of the query per replica
    query_result = query.group_by(models.RSEFileAssociation.rse_id, bad_replicas_alias.scope, bad_replicas_alias.name).having(func.count() > nattempts).all()
    # print(query)
    # translating the rse_id to RSE name and assembling the return list of dictionaries
    result = []
    rses = {}
    for cnt, scope, name, rse_id, created_at in query_result:
        if rse_id not in rses:
            rse = get_rse_name(rse_id=rse_id, session=session)
            rses[rse_id] = rse
        result.append({'scope': scope, 'name': name, 'rse': rses[rse_id], 'rse_id': rse_id, 'cnt': cnt, 'created_at': created_at})

    return result


@transactional_session
def set_tombstone(rse_id, scope, name, tombstone=OBSOLETE, session=None):
    """
    Sets a tombstone on a replica.

    :param rse_id: ID of RSE.
    :param scope: scope of the replica DID.
    :param name: name of the replica DID.
    :param tombstone: the tombstone to set. Default is OBSOLETE
    :param session: database session in use.
    """
    rowcount = session.query(models.RSEFileAssociation).filter(
        and_(
            models.RSEFileAssociation.rse_id == rse_id,
            models.RSEFileAssociation.name == name,
            models.RSEFileAssociation.scope == scope,
            ~exists().where(
                and_(
                    models.ReplicaLock.rse_id == rse_id,
                    models.ReplicaLock.name == name,
                    models.ReplicaLock.scope == scope,
                )
            )
        )
    ) \
        .with_hint(models.RSEFileAssociation, "index(REPLICAS REPLICAS_PK)", 'oracle') \
        .update({models.RSEFileAssociation.tombstone: tombstone}, synchronize_session=False)

    if rowcount == 0:
        try:
            session.query(models.RSEFileAssociation).filter_by(scope=scope, name=name, rse_id=rse_id).one()
            raise exception.ReplicaIsLocked('Replica %s:%s on RSE %s is locked.' % (scope, name, get_rse_name(rse_id=rse_id, session=session)))
        except NoResultFound:
            raise exception.ReplicaNotFound('Replica %s:%s on RSE %s could not be found.' % (scope, name, get_rse_name(rse_id=rse_id, session=session)))


@read_session
def get_RSEcoverage_of_dataset(scope, name, session=None):
    """
    Get total bytes present on RSEs

    :param scope:             Scope of the dataset
    :param name:              Name of the dataset
    :param session:           The db session.
    :return:                  Dictionary { rse_id : <total bytes present at rse_id> }
    """

    query = session.query(models.RSEFileAssociation.rse_id, func.sum(models.DataIdentifierAssociation.bytes))

    query = query.filter(and_(models.DataIdentifierAssociation.child_scope == models.RSEFileAssociation.scope,
                              models.DataIdentifierAssociation.child_name == models.RSEFileAssociation.name,
                              models.DataIdentifierAssociation.scope == scope,
                              models.DataIdentifierAssociation.name == name,
                              models.RSEFileAssociation.state != ReplicaState.BEING_DELETED,
                              ))

    query = query.group_by(models.RSEFileAssociation.rse_id)

    result = {}

    for rse_id, total in query:
        if total:
            result[rse_id] = total

    return result
