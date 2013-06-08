# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012-2013
# - Yun-Pin Sun, <yun-pin.sun@cern.ch>, 2013
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013
# - Martin Barisits, <martin.barisits@cern.ch>, 2013

from datetime import datetime, timedelta
from re import match

from sqlalchemy import or_, Column
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql import not_
from sqlalchemy.sql.expression import bindparam

from rucio.common import exception
from rucio.common.constraints import AUTHORIZED_VALUE_TYPES
from rucio.core.rse import add_file_replica
from rucio.db import models
from rucio.db.constants import DIDType, DIDReEvaluation, ReplicaState, KeyType
from rucio.db.session import read_session, transactional_session
from rucio.rse import rsemanager


@read_session
def list_replicas(scope, name, schemes=None, session=None):
    """
    List file replicas for a data identifier.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param schemes: A list of schemes to filter the replicas. (e.g. file, http, ...)
    :param session: The database session in use.

    """
    rsemgr = rsemanager.RSEMgr(server_mode=True)
    try:
        query = session.query(models.RSEFileAssociation).filter_by(scope=scope, name=name, state=ReplicaState.AVAILABLE)
        for row in query.yield_per(5):
            try:
                pfns = list()
                for protocol in rsemgr.list_protocols(rse_id=row.rse.rse):
                    if not schemes or protocol['scheme'] in schemes:
                        pfns.append(rsemgr.lfn2pfn(rse_id=row.rse.rse, lfns={'scope': scope, 'filename': name}, properties=protocol))
                if pfns:
                    yield {'scope': row.scope, 'name': row.name, 'bytes': row.bytes,
                           'rse': row.rse.rse, 'md5': row.md5, 'adler32': row.adler32, 'pfns': pfns}
            except (exception.RSENotFound, exception.RSEProtocolNotSupported):
                pass
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found")


@read_session
def list_dids(scope, pattern, type='collection', ignore_case=False, session=None):
    """
    List dids in a scope.

    :param scope: The scope name.
    :param pattern: The wildcard pattern.
    :param type:  The type of the did: all(container, dataset, file), collection(dataset or container), dataset, container, file.
    :param ignore_case: Ignore case distinctions.
    :param session: The database session in use.
    """

    query = session.query(models.DataIdentifier).filter(models.DataIdentifier.name.like(pattern.replace('*', '%')))
    # if ignore_case
    # func.upper(models.DataIdentifier.name).like(pattern.replace('*','%'))
    if type == 'all':
        query = query.filter(or_(models.DataIdentifier.did_type == DIDType.CONTAINER,
                                 models.DataIdentifier.did_type == DIDType.DATASET,
                                 models.DataIdentifier.did_type == DIDType.FILE))
    elif type == 'collection':
        query = query.filter(or_(models.DataIdentifier.did_type == DIDType.CONTAINER, models.DataIdentifier.did_type == DIDType.DATASET))
    elif type == 'container':
        query = query.filter(models.DataIdentifier.did_type == DIDType.CONTAINER)
    elif type == 'dataset':
        query = query.filter(models.DataIdentifier.did_type == DIDType.DATASET)
    elif type == 'file':
        query = query.filter(models.DataIdentifier.did_type == DIDType.FILE)
    #else:
    #  error
    for row in query.yield_per(5):
        d = {}
        for column in row.__table__.columns:
            d[column.name] = getattr(row, column.name)
        yield d


@transactional_session
def add_identifier(scope, name, type, account, statuses={}, meta=[], rules=[], lifetime=None, session=None):
    """
    Add data identifier.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param type: The data identifier type.
    :param account: The account owner.
    :param statuses: Dictionary with statuses, e.g.g {'monotonic':True}.
    :meta: Meta-data associated with the data identifier is represented using key/value pairs in a dictionary.
    :rules: Replication rules associated with the data identifier. A list of dictionaries, e.g., [{'copies': 2, 'rse_expression': 'TIERS1'}, ].
    :param lifetime: DID's lifetime (in seconds).
    :param session: The database session in use.
    """
    if type == DIDType.FILE:
        raise exception.UnsupportedOperation("Only collection (dataset/container) can be registered." % locals())

    # Lifetime
    expired_at = None
    if lifetime:
        expired_at = datetime.utcnow() + timedelta(seconds=lifetime)

    # Insert new data identifier
    new_did = models.DataIdentifier(scope=scope, name=name, account=account, did_type=type, monotonic=statuses.get('monotonic', False), is_open=True, expired_at=expired_at)

    # Add meta-data
    for key in meta:
        new_did.update({key: meta[key]})

    try:
        new_did.save(session=session)
    except IntegrityError, e:
        if e.args[0] == "(IntegrityError) columns scope, name are not unique":
            raise exception.DataIdentifierAlreadyExists('Data identifier %(scope)s:%(name)s already exists!' % locals())
        elif e.args[0] == "(IntegrityError) foreign key constraint failed":
            raise exception.ScopeNotFound('Scope %(scope)s not found!' % locals())
        # msg for oracle / mysql
        raise exception.RucioException(e.args[0])

    # Add meta-data
    for key in meta:
        set_metadata(scope=scope, name=name, key=key, value=meta[key], type=type, did=new_did, session=session)

    # Add rules
    # for rule in rules:
    #    add_replication_rule(dids=[{'scope': scope, 'name': name}, ], account=issuer, copies=rule['copies'],
    #                         rse_expression=rule['rse_expression'], parameters={}, session=session)  # lifetime + grouping


@transactional_session
def attach_identifier(scope, name, dids, account, session=None):
    """
    Append data identifier.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param dids: The content.
    :param account: The account owner.
    :param session: The database session in use.
    """

    query = session.query(models.DataIdentifier).with_lockmode('update').filter_by(scope=scope, name=name).\
        filter(or_(models.DataIdentifier.did_type == DIDType.CONTAINER, models.DataIdentifier.did_type == DIDType.DATASET))
    try:
        did = query.one()

        if not did.is_open:
            raise exception.UnsupportedOperation("Data identifier '%(scope)s:%(name)s' is closed" % locals())

        if did.did_type == DIDType.FILE:
            raise exception.UnsupportedOperation("Data identifier '%(scope)s:%(name)s' is a file" % locals())
        elif did.did_type == DIDType.DATASET:
            child_type = DIDType.FILE
        elif did.did_type == DIDType.CONTAINER:
            child_type = None  # collection: DIDType.DATASET or DIDType.CONTAINER

    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())

    # Mark for rule re-evaluation
    if did.rule_evaluation_action is None:
        did.rule_evaluation_action = DIDReEvaluation.ATTACH
    elif did.rule_evaluation_action == DIDReEvaluation.DETACH:
        did.rule_evaluation_action = DIDReEvaluation.BOTH

    query_all = session.query(models.DataIdentifier)
    # query_associ = session.query(models.DataIdentifierAssociation).filter_by(scope=scope, name=name, did_type=did.did_type)
    for source in dids:

        if (scope == source['scope']) and (name == source['name']):
            raise exception.UnsupportedOperation('Self-append is not valid.')

        if did.did_type == DIDType.CONTAINER:
            try:

                child = query_all.filter_by(scope=source['scope'], name=source['name']).one()

                if child.did_type == DIDType.FILE:
                    raise exception.UnsupportedOperation("File '%(scope)s:%(name)s' " % source + "cannot be associated with a container '%(scope)s:%(name)s' is a file" % locals())

                if not child_type:
                    child_type = child.did_type
                elif child_type != child.did_type:
                    raise exception.UnsupportedOperation("Mixed collection is not allowed: '%(scope)s:%(name)s' " % source + "is a %s(expected type: %s)" % (child.did_type, child_type))

            except NoResultFound:
                raise exception.DataIdentifierNotFound("Source data identifier '%(scope)s:%(name)s' not found" % source)

        elif did.did_type == DIDType.DATASET:

            if child_type == DIDType.FILE and 'bytes' not in source:
                raise exception.MissingFileParameter("The file bytes is missing for file '%(scope)s:%(name)s'" % source)

            if child_type == DIDType.FILE and 'rse' in source:
                add_file_replica(account=account, session=session, **source)
            else:
                try:
                    child = query_all.filter_by(scope=source['scope'], name=source['name']).one()
                    if child.did_type != DIDType.FILE:
                        raise exception.UnsupportedOperation("Mixed collection is not allowed: '%(scope)s:%(name)s' " % source + "is a %s(expected type: %s)" % (child.did_type, child_type))

                    if source['bytes'] != child.bytes or source.get('adler32', None) != child.adler32 or source.get('md5', None) != child.md5:
                        errMsg = "(bytes: %s, adler32: '%s', md5: '%s') != " % (source['bytes'], source.get('adler32', None), source.get('md5', None)) + "(bytes: %s, adler32: '%s', md5: '%s')" % (child.bytes, child.adler32, child.md5)
                        raise exception.FileConsistencyMismatch(errMsg)
                except NoResultFound:
                    raise exception.DataIdentifierNotFound("Source file '%(scope)s:%(name)s' not found" % source)

        try:
            models.DataIdentifierAssociation(scope=scope, name=name, child_scope=source['scope'], child_name=source['name'],
                                             bytes=source.get('bytes', None), adler32=source.get('adler32', None),
                                             md5=source.get('md5', None), did_type=did.did_type, child_type=child_type).save(session=session)
        except IntegrityError, e:
            raise exception.RucioException(e.args[0])
            #if e.args[0] == "(IntegrityError) foreign key constraint failed":
            # append_did = query_associ.filter_by(child_scope=source['scope'], child_name=source['name'], child_type=child_type).first()
            #if append_did and append_did.deleted:
            #    append_did.update({'deleted': False})
            #else:
            #    raise exception.DuplicateContent('The data identifier {0[source][scope]}:{0[source][name]} has been already added to {0[scope]}:{0[name]}.'.format(locals()))

        if 'meta' in source:
            for key in source['meta']:
                set_metadata(scope=source['scope'], name=source['name'], key=key, type=child_type, value=source['meta'][key], session=session)


@transactional_session
def detach_identifier(scope, name, dids, issuer, session=None):
    """
    Detach data identifier

    :param scope: The scope name.
    :param name: The data identifier name.
    :param dids: The content.
    :param issuer: The issuer account.
    :param session: The database session in use.
    """

    #Row Lock the parent did
    query = session.query(models.DataIdentifier).with_lockmode('update').filter_by(scope=scope, name=name)  # add type
    try:
        did = query.one()
        # Mark for rule re-evaluation
        if did.rule_evaluation_action is None:
            did.rule_evaluation_action = DIDReEvaluation.DETACH
        elif did.rule_evaluation_action == DIDReEvaluation.ATTACH:
            did.rule_evaluation_action = DIDReEvaluation.BOTH
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())

    #TODO: should judge target did's status: open, monotonic, close.
    query_all = session.query(models.DataIdentifierAssociation).filter_by(scope=scope, name=name)
    if query_all.first() is None:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' has no child data identifiers." % locals())
    for source in dids:
        if (scope == source['scope']) and (name == source['name']):
            raise exception.UnsupportedOperation('Self-detach is not valid.')
        child_scope = source['scope']
        child_name = source['name']
        associ_did = query_all.filter_by(child_scope=child_scope, child_name=child_name).first()
        if associ_did is None:
            raise exception.DataIdentifierNotFound("Data identifier '%(child_scope)s:%(child_name)s' not found under '%(scope)s:%(name)s'" % locals())
        associ_did.delete(session=session)


@read_session
def list_rule_re_evaluation_identifier(limit=None, session=None):
    """
    List identifiers which need rule re-evaluation.

    :param type : The DID type.
    """
    query = session.query(models.DataIdentifier.scope, models.DataIdentifier.name, models.DataIdentifier.did_type).filter_by(rule_evaluation=True)

    if limit:
        query = query.limit(limit)
    for scope, name, did_type in query.yield_per(10):
        yield {'scope': scope, 'name': name, 'type': did_type}


@read_session
def list_new_identifier(type, session=None):
    """
    List recent identifiers.

    :param type : The DID type.
    :param session: The database session in use.
    """
    if type:
        query = session.query(models.DataIdentifier).filter_by(did_type=type, is_new=1)
    else:
        query = session.query(models.DataIdentifier).filter_by(is_new=1)
    for chunk in query.yield_per(10):
        yield {'scope': chunk.scope, 'name': chunk.name, 'type': chunk.did_type}  # TODO Change this to the proper filebytes [RUCIO-199]


@transactional_session
def set_new_identifier(scope, name, new_flag, session=None):
    """
    Set/reset the flag new

    :param scope: The scope name.
    :param name: The data identifier name.
    :param new_flag: A boolean to flag new DIDs.
    :param session: The database session in use.
    """

    query = session.query(models.DataIdentifier).filter_by(scope=scope, name=name)
    rowcount = query.update({'is_new': new_flag})

    if not rowcount:
        query = session.query(models.DataIdentifier).filter_by(scope=scope, name=name)
        try:
            query.one()
        except NoResultFound:
            raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())
        raise exception.UnsupportedOperation("The new flag of the data identifier '%(scope)s:%(name)s' cannot be changed" % locals())
    else:
        return rowcount


@read_session
def list_content(scope, name, session=None):
    """
    List data identifier contents.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param session: The database session in use.
    """
    try:
        query = session.query(models.DataIdentifierAssociation).filter_by(scope=scope, name=name)
        for tmp_did in query.yield_per(5):
            yield {'scope': tmp_did.child_scope, 'name': tmp_did.child_name, 'type': tmp_did.child_type,
                   'bytes': tmp_did.bytes, 'adler32': tmp_did.adler32, 'md5': tmp_did.md5}
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())


@read_session
def list_parent_dids(scope, name, lock=False, session=None):
    """
    List all parent datasets and containers of a did.

    :param scope:    The scope.
    :param name:     The name.
    :param lock:     If the rows should be locked.
    :param session:  The database session.
    :returns:        List of dids.
    :rtype:          Generator.
    """

    query = session.query(models.DataIdentifierAssociation.scope,
                          models.DataIdentifierAssociation.name,
                          models.DataIdentifierAssociation.did_type).filter_by(child_scope=scope, child_name=name)
    if lock:
        query = query.with_lockmode('update')
    for did in query.yield_per(5):
        yield {'scope': did.scope, 'name': did.name, 'type': did.did_type}
        list_parent_dids(scope=did.scope, name=did.name, session=session)


@read_session
def list_child_dids(scope, name, lock=False, session=None):
    """
    List all child datasets and containers of a did.

    :param scope:    The scope.
    :param name:     The name.
    :param lock:     If the rows should be locked.
    :param session:  The database session
    :returns:        List of dids
    :rtype:          Generator
    """

    query = session.query(models.DataIdentifierAssociation.child_scope,
                          models.DataIdentifierAssociation.child_name,
                          models.DataIdentifierAssociation.child_type).filter(
                              models.DataIdentifierAssociation.scope == scope,
                              models.DataIdentifierAssociation.name == name,
                              models.DataIdentifierAssociation.child_type != DIDType.FILE)
    if lock:
        query = query.with_lockmode('update')
    for child_scope, child_name, child_type in query.yield_per(5):
        yield {'scope': child_scope, 'name': child_name, 'type': child_type}
        if child_type == 'container':
            list_child_dids(scope=child_scope, name=child_name, session=session)


@read_session
def list_files(scope, name, session=None):
    """
    List data identifier file contents.

    :param scope:      The scope name.
    :param name:       The data identifier name.
    :param session:    The database session in use.
    """

    query = session.query(models.DataIdentifier).filter_by(scope=scope, name=name)   # avoid deleted data
    try:
        did = query.one()
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())

    if did.did_type == DIDType.FILE:
        yield {'scope': did.scope, 'name': did.name, 'bytes': did.bytes, 'adler32': did.adler32}
    else:
        query = session.query(models.DataIdentifierAssociation)
        dids = [(scope, name), ]
        while dids:
            s, n = dids.pop()
            for tmp_did in query.filter_by(scope=s, name=n).yield_per(5):
                if tmp_did.child_type == DIDType.FILE:
                    yield {'scope': tmp_did.child_scope, 'name': tmp_did.child_name,
                           'bytes': tmp_did.bytes, 'adler32': tmp_did.adler32}
                else:
                    dids.append((tmp_did.child_scope, tmp_did.child_name))


@read_session
def scope_list(scope, name=None, recursive=False, session=None):
    """
    List data identifiers in a scope.

    :param scope: The scope name.
    :param session: The database session in use.
    :param name: The data identifier name.
    :param recursive: boolean, True or False.
    """
    # TODO= Perf. tuning of the method
    # query = session.query(models.DataIdentifier).filter_by(scope=scope, deleted=False)
    # for did in query.yield_per(5):
    #    yield {'scope': did.scope, 'name': did.name, 'type': did.did_type, 'parent': None, 'level': 0}

    def __topdids(scope):
        c = session.query(models.DataIdentifierAssociation.child_name).filter_by(scope=scope, child_scope=scope)
        q = session.query(models.DataIdentifier.name, models.DataIdentifier.did_type).filter_by(scope=scope)  # add type
        s = q.filter(not_(models.DataIdentifier.name.in_(c))).order_by(models.DataIdentifier.name)
        for row in s.yield_per(5):
            yield {'scope': scope, 'name': row.name, 'type': row.did_type, 'parent': None, 'level': 0}

    def __diddriller(pdid):
        query_associ = session.query(models.DataIdentifierAssociation).filter_by(scope=pdid['scope'], name=pdid['name'])
        for row in query_associ.order_by('child_name').yield_per(5):
            parent = {'scope': pdid['scope'], 'name': pdid['name']}
            cdid = {'scope': row.child_scope, 'name': row.child_name, 'type': row.child_type, 'parent': parent, 'level': pdid['level'] + 1}
            yield cdid
            if cdid['type'] != DIDType.FILE and recursive:
                for did in __diddriller(cdid):
                    yield did

    if name is None:
        topdids = __topdids(scope)
    else:
        topdids = session.query(models.DataIdentifier).filter_by(scope=scope, name=name).first()
        if topdids is None:
            raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())
        topdids = [{'scope': topdids.scope, 'name': topdids.name, 'type': topdids.did_type, 'parent': None, 'level': 0}]

    if name is None:
        for topdid in topdids:
            yield topdid
            if recursive:
                for did in __diddriller(topdid):
                    yield did
    else:
        for topdid in topdids:
            for did in __diddriller(topdid):
                yield did


@read_session
def get_did(scope, name, session=None):
    """
    Retrieve a single data identifier.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param session: The database session in use.
    """

    did_r = {'scope': None, 'name': None, 'type': None}
    try:
        r = session.query(models.DataIdentifier).filter_by(scope=scope, name=name).one()  # removed deleted types
        if r:
            if r.did_type == DIDType.FILE:
                did_r = {'scope': r.scope, 'name': r.name, 'type': r.did_type, 'account': r.account}
            else:
                did_r = {'scope': r.scope, 'name': r.name, 'type': r.did_type,
                         'account': r.account, 'open': r.is_open, 'monotonic': r.monotonic, 'expired_at': r.expired_at}

            #  To add:  created_at, updated_at, deleted_at, deleted, monotonic, hidden, obsolete, complete
            #  ToDo: Add json encoder for datetime
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())

    return did_r


@transactional_session
def set_metadata(scope, name, key, value, type=None, did=None, session=None):
    """
    Add metadata to data identifier.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param key: the key.
    :param value: the value.
    :paran did: The data identifier info.
    :param session: The database session in use.
    """
    # Check enum types
    enum = session.query(models.DIDKeyValueAssociation).filter_by(key=key).first()
    if enum:
        try:
            session.query(models.DIDKeyValueAssociation).filter_by(key=key, value=value).one()
        except NoResultFound:
            raise exception.InvalidValueForKey("The value '%(value)s' is invalid for the key '%(key)s'" % locals())

    # Check constraints
    try:
        k = session.query(models.DIDKey).filter_by(key=key).one()
    except NoResultFound:
        raise exception.KeyNotFound("'%(key)s' not found." % locals())

    # Check value against regexp, if defined
    if k.value_regexp and not match(k.value_regexp, str(value)):
        raise exception.InvalidValueForKey("The value '%s' for the key '%s' does not match the regular expression '%s'" % (value, key, k.value_regexp))

    # Check value type, if defined
    type_map = dict([(str(t), t) for t in AUTHORIZED_VALUE_TYPES])
    if k.value_type and not isinstance(value, type_map.get(k.value_type)):
            raise exception.InvalidValueForKey("The value '%s' for the key '%s' does not match the required type '%s'" % (value, key, k.value_type))

    if not did:
        did = get_did(scope=scope, name=name, session=session)

    # Check key_type
    if k.key_type in (KeyType.FILE, KeyType.DERIVED) and did['type'] != DIDType.FILE:
        raise exception.UnsupportedOperation("The key '%(key)s' cannot be applied on data identifier with type != file" % locals())
    elif k.key_type == KeyType.COLLECTION and did['type'] not in (DIDType.DATASET, DIDType.CONTAINER):
        raise exception.UnsupportedOperation("The key '%(key)s' cannot be applied on data identifier with type != dataset|container" % locals())

    # models.DataIdentifier.__table__.append_column(Column(key, models.String(50)))
    session.query(models.DataIdentifier).filter_by(scope=scope, name=name).update({key: value}, synchronize_session='fetch')  # add DIDtype
    # values = {key: value}
    # stmt = models.DataIdentifier.__table__.update().where(models.DataIdentifier.__table__.c.scope == bindparam('s')).where(models.DataIdentifier.__table__.c.name == bindparam('n')).values(**values)
    # session.execute(stmt, [{'s': scope, 'n': name}, ])


#    if key == 'guid':
#        try:
#            session.query(models.DataIdentifier).filter_by(scope=scope, name=name).update({'guid': value}, synchronize_session='fetch')  # add DIDtype
#            # or synchronize_session=False
#            # session.expire_all() ?
#        except IntegrityError, e:
#            raise exception.Duplicate('Metadata \'%(key)s-%(value)s\' already exists for a file!' % locals())
    # else:
    #    new_meta = models.DIDAttribute(scope=scope, name=name, key=key, value=value, did_type=did['did_type'])
    #    try:
    #        new_meta.save(session=session)
    #    except IntegrityError, e:
    #        print e.args[0]
    #        if e.args[0] == "(IntegrityError) foreign key constraint failed":
    #            raise exception.KeyNotFound("Key '%(key)s' not found" % locals())
    #        if e.args[0] == "(IntegrityError) columns scope, name, key are not unique":
    #            raise exception.Duplicate('Metadata \'%(key)s-%(value)s\' already exists!' % locals())
    #        raise


@read_session
def get_metadata(scope, name, session=None):
    """
    Get data identifier metadata

    :param scope: The scope name.
    :param name: The data identifier name.
    :param session: The database session in use.
    """
    for key in session.query(models.DIDKey):
        models.DataIdentifier.__table__.append_column(Column(key.key, models.String(50)))

    try:
        r = session.query(models.DataIdentifier.__table__).filter_by(scope=scope, name=name).one()   # remove deleted data
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())

    meta = {}
    for column in r._fields:
        meta[column] = getattr(r, column)

    # if r.did_type == DIDType.FILE and r.guid:
    #    meta['guid'] = r.guid

    return meta


@transactional_session
def set_status(scope, name, session=None, **kwargs):
    """
    Set data identifier status

    :param scope: The scope name.
    :param name: The data identifier name.
    :param session: The database session in use.
    :param kwargs:  Keyword arguments of the form status_name=value.
    """
    statuses = ['open', ]

    query = session.query(models.DataIdentifier).filter_by(scope=scope, name=name)   # need to add the DIDType
    values = {}
    for k in kwargs:
        if k not in statuses:
            raise exception.UnsupportedStatus("The status %(k)s is not a valid data identifier status." % locals())
        if k == 'open':
            query = query.filter_by(is_open=True).filter(models.DataIdentifier.did_type != DIDType.FILE)
            values['is_open'] = False

    rowcount = query.update(values, synchronize_session='fetch')

    if not rowcount:
        query = session.query(models.DataIdentifier).filter_by(scope=scope, name=name)
        try:
            query.one()
        except NoResultFound:
            raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())
        raise exception.UnsupportedOperation("The status of the data identifier '%(scope)s:%(name)s' cannot be changed" % locals())
