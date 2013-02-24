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

from re import match

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound

from rucio.common import exception
from rucio.common.constraints import AUTHORIZED_VALUE_TYPES
from rucio.core.rse import add_file_replica
from rucio.db import models
from rucio.db.session import read_session, transactional_session
from rucio.rse import rsemanager


@read_session
def list_replicas(scope, name, protocols=None, session=None):
    """
    List file replicas for a data identifier.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param protocols: A list of protocols to filter the replicas.
    :param session: The database session in use.

    """

    rsemgr = rsemanager.RSEMgr()
    try:
        query = session.query(models.RSEFileAssociation).filter_by(scope=scope, name=name, state='AVAILABLE', deleted=False)
        for row in query:
            try:
                pfns = list()
                for protocol in rsemgr.list_protocols(rse_id=row.rse.rse):
                    if not protocols or protocol in protocols:
                        pfns.append(rsemgr.lfn2pfn(rse_id=row.rse.rse, scope=scope, lfn=name, protocol=protocol))

                # ToDo: add support for non determistic rse path -> pfn conversion
                if pfns:
                    yield {'scope': row.scope, 'name': row.name, 'size': row.size,
                           'rse': row.rse.rse, 'checksum': row.checksum, 'pfns': pfns}
            except (exception.RSENotFound, exception.SwitchProtocol):
                pass
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found")


@transactional_session
def add_identifier(scope, name, type, issuer, statuses={}, meta=[], rules=[], session=None):
    """
    Add data identifier.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param type: The data identifier type.
    :param issuer: The issuer account.
    :param statuses: Dictionary with statuses, e.g.g {'monotonic':True}.
    :meta: Meta-data associated with the data identifier is represented using key/value pairs in a dictionary.
    :rules: Replication rules associated with the data identifier. A list of dictionaries, e.g., [{'copies': 2, 'rse_expression': 'TIERS1'}, ].
    :param session: The database session in use.
    """
    if type == models.DataIdType.FILE:
        raise exception.UnsupportedOperation("Only dataset/container can be registered." % locals())

    # Insert new data identifier
    new_did = models.DataIdentifier(scope=scope, name=name, owner=issuer, type=type, monotonic=statuses.get('monotonic', False), open=True)
    try:
        new_did.save(session=session)
    except IntegrityError, e:
        if e.args[0] == "(IntegrityError) columns scope, name are not unique":
            raise exception.DataIdentifierAlreadyExists('Data identifier %(scope)s:%(name)s already exists!' % locals())
        elif e.args[0] == "(IntegrityError) foreign key constraint failed":
            raise exception.ScopeNotFound('Scope %(scope)s not found!' % locals())
        # msg for oracle / mysql
        else:
            raise e

    # Add meta-data
    for key in meta:
        set_metadata(scope=scope, name=name, key=key, value=meta[key], did=new_did, session=session)

    # Add rules
    # for rule in rules:
    #    add_replication_rule(dids=[{'scope': scope, 'name': name}, ], account=issuer, copies=rule['copies'],
    #                         rse_expression=rule['rse_expression'], parameters={}, session=session)  # lifetime + grouping


@transactional_session
def append_identifier(scope, name, dids, issuer, session=None):
    """
    Append data identifier.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param dids: The content.
    :param issuer: The issuer account.
    :param session: The database session in use.
    """
    #TODO: should judge target did's status: open, monotonic, close.
    query = session.query(models.DataIdentifier).filter_by(scope=scope, name=name, deleted=False)
    try:
        did = query.one()
        if not did.open:
            raise exception.UnsupportedOperation("Data identifier '%(scope)s:%(name)s' is closed" % locals())
        if did.type == models.DataIdType.FILE:
            raise exception.UnsupportedOperation("Data identifier '%(scope)s:%(name)s' is a file" % locals())
        elif did.type == models.DataIdType.DATASET:
            child_type = models.DataIdType.FILE
        elif did.type == models.DataIdType.CONTAINER:
            child_type = models.DataIdType.DATASET
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())

    query_all = session.query(models.DataIdentifier)
    query_associ = session.query(models.DataIdentifierAssociation).filter_by(scope=scope, name=name, type=did.type)
    for source in dids:
        if did.type == models.DataIdType.CONTAINER:
            child = query_all.filter_by(scope=source['scope'], name=source['name'], deleted=False).first()
            if child is None:
                raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())
            child_type = child.type
        if 'rse' in source:
            add_file_replica(issuer=issuer, session=session, **source)

        append_did = query_associ.filter_by(child_scope=source['scope'], child_name=source['name'], child_type=child_type).first()
        if append_did is None:
            models.DataIdentifierAssociation(scope=scope, name=name, child_scope=source['scope'], child_name=source['name'], type=did.type, child_type=child_type).save(session=session)
        else:
            if append_did.deleted:
                append_did.update({'deleted': False})
            else:
                raise exception.DuplicateContent('The data identifier {0[source][scope]}:{0[source][name]} has been already added to {0[scope]}:{0[name]}.'.format(locals()))

        if 'meta' in source:
            for key in source['meta']:
                set_metadata(scope=source['scope'], name=source['name'], key=key, value=source['meta'][key], session=session)


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

    #TODO: should judge target did's status: open, monotonic, close.
    query_all = session.query(models.DataIdentifierAssociation).filter_by(scope=scope, name=name, deleted=False)
    if query_all.first() is None:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())
    for source in dids:
        child_scope = source['scope']
        child_name = source['name']
        associ_did = query_all.filter_by(child_scope=child_scope, child_name=child_name).first()
        if associ_did is None:
            raise exception.DataIdentifierNotFound("Data identifier '%(child_scope)s:%(child_name)s' not found under '%(scope)s:%(name)s'" % locals())
        associ_did.delete(soft=False, session=session)


@read_session
def list_content(scope, name, session=None):
    """
    List data identifier contents.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param session: The database session in use.
    """

    dids = []
    try:
        query = session.query(models.DataIdentifierAssociation).filter_by(scope=scope, name=name, deleted=False)
        for tmp_did in query:
            dids.append({'scope': tmp_did.child_scope, 'name': tmp_did.child_name, 'type': tmp_did.child_type})
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())

    return dids


@read_session
def list_files(scope, name, session=None):
    """
    List data identifier file contents.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param session: The database session in use.
    """

    query = session.query(models.DataIdentifier).filter_by(scope=scope, name=name, deleted=False)
    try:
        did = query.one()
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())

    if did.type == models.DataIdType.FILE:
        yield {'scope': did.scope, 'name': did.name}
    else:
        dids = [(scope, name), ]
        while dids:
            s, n = dids.pop()
            query = session.query(models.DataIdentifierAssociation).filter_by(scope=s, name=n, deleted=False)
            for tmp_did in query:
                if tmp_did.child_type == models.DataIdType.FILE:
                    yield {'scope': tmp_did.child_scope, 'name': tmp_did.child_name}
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

    try:
        query_all = session.query(models.DataIdentifier).filter_by(scope=scope, deleted=False)
        query_associ = session.query(models.DataIdentifierAssociation).filter_by(scope=scope, deleted=False)
    except NoResultFound:
        raise exception.ScopeNotFound("Scope '%(scope)s' not found" % scope)

    def __topdids(scope):
        topdids = []
        q = session.query(models.DataIdentifier.name, models.DataIdentifier.type).filter_by(scope=scope, deleted=False)
        a = session.query(models.DataIdentifierAssociation.child_name, models.DataIdentifierAssociation.child_type).filter_by(scope=scope, deleted=False)
        s = q.except_(a)
        for row in s.all():
            topdids.append({'scope': scope, 'name': row.name, 'type': row.type, 'parent': None, 'level': 0})
        return topdids

    def __didtree(topdids, parent=None, level=0, depth=-1):
        # depth > 0 for limited recursive, -1 for complete recursive
        dids = []
        for pdid in topdids:
            dids.append({'scope': pdid['scope'], 'name': pdid['name'], 'type': pdid['type'], 'parent': parent, 'level': level})
            if pdid['type'] != models.DataIdType.FILE and (depth > 0 or depth == -1):
                if depth != -1:
                    depth -= 1
                try:
                    for row in query_associ.filter_by(name=pdid['name']):
                        cdid = {'scope': row.child_scope, 'name': row.child_name, 'type': row.child_type}
                        dids.extend(__didtree([cdid], parent={'scope': row.scope, 'name': row.name}, level=level + 1, depth=depth))
                except NoResultFound:
                    raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())
        return dids

    if name:
        try:
            topdids = query_all.filter_by(name=name).one()
        except NoResultFound:
            raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())
        topdids = [{'scope': topdids.scope, 'name': topdids.name, 'type': topdids.type}]
        if recursive:
            response = __didtree(topdids)
        else:
            response = __didtree(topdids, depth=1)
    else:
        topdids = __topdids(scope)
        if recursive:
            response = __didtree(topdids)
        else:
            response = topdids

    for did in response:
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
        r = session.query(models.DataIdentifier).filter_by(scope=scope, name=name, deleted=False).one()
        if r:
            if r.type == models.DataIdType.FILE:
                did_r = {'scope': r.scope, 'name': r.name, 'type': r.type, 'owner': r.owner}
            else:
                did_r = {'scope': r.scope, 'name': r.name, 'type': r.type,
                         'owner': r.owner, 'open': r.open, 'monotonic': r.monotonic}

            #  To add:  created_at, updated_at, deleted_at, deleted, monotonic, hidden, obsolete, complete
            #  ToDo: Add json encoder for datetime
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())

    return did_r


@transactional_session
def set_metadata(scope, name, key, value, did=None, session=None):
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
    enum = session.query(models.DIDKeyValueAssociation).filter_by(key=key, deleted=False).first()
    if enum:
        try:
            session.query(models.DIDKeyValueAssociation).filter_by(key=key, deleted=False, value=value).one()
        except NoResultFound:
            raise exception.InvalidValueForKey('The value %(value)s is invalid for the key %(key)s' % locals())

    # Check constraints
    try:
        k = session.query(models.DIDKey).filter_by(key=key).one()
    except NoResultFound:
        raise exception.KeyNotFound('%(key)s not found.' % locals())

    # Check value against regexp, if defined
    if k.value_regexp and not match(k.value_regexp, str(value)):
        raise exception.InvalidValueForKey('The value %s for the key %s does not match the regular expression %s' % (value, key, k.value_regexp))

    # Check value type, if defined
    type_map = dict([(str(t), t) for t in AUTHORIZED_VALUE_TYPES])
    if k.value_type and not isinstance(value, type_map.get(k.value_type)):
            raise exception.InvalidValueForKey('The value %s for the key %s does not match the required type %s' % (value, key, k.value_type))

    if not did:
        did = get_did(scope=scope, name=name, session=session)

    # Check key_type
    if k.key_type in ('file', 'derived') and did['type'] != 'file':
        raise exception.UnsupportedOperation("The key %(key)s cannot be applied on data identifier with type != file" % locals())
    elif k.key_type == 'collection' and did['type'] not in ('dataset', 'container'):
        raise exception.UnsupportedOperation("The key %(key)s cannot be applied on data identifier with type != dataset|container" % locals())

    if key == 'guid':
        try:
            session.query(models.File).filter_by(scope=scope, name=name, deleted=False).update({'guid': value})
        except IntegrityError, e:
            raise exception.Duplicate('Metadata \'%(key)s-%(value)s\' already exists for a file!' % locals())
    else:
        new_meta = models.DIDAttribute(scope=scope, name=name, key=key, value=value)
        try:
            new_meta.save(session=session)
        except IntegrityError, e:
            print e.args[0]
            if e.args[0] == "(IntegrityError) foreign key constraint failed":
                raise exception.KeyNotFound("Key '%(key)s' not found" % locals())
            if e.args[0] == "(IntegrityError) columns scope, name, key are not unique":
                raise exception.Duplicate('Metadata \'%(key)s-%(value)s\' already exists!' % locals())
            raise


@read_session
def get_metadata(scope, name, session=None):
    """
    Get data identifier metadata

    :param scope: The scope name.
    :param name: The data identifier name.
    :param session: The database session in use.
    """
    try:
        r = session.query(models.DataIdentifier).filter_by(scope=scope, name=name, deleted=False).one()
    except NoResultFound:
        raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())

    meta = {}
    query = session.query(models.DIDAttribute).filter_by(scope=scope, name=name, deleted=False)
    for row in query:
        meta[row.key] = row.value

    if r.type == models.DataIdType.FILE:
        row = session.query(models.File).filter_by(scope=scope, name=name, deleted=False).first()
        if row.guid:
            meta['guid'] = row.guid

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

    query = session.query(models.DataIdentifier).filter_by(scope=scope, name=name, deleted=False)
    values = {}
    for k in kwargs:
        if k not in statuses:
            raise exception.UnsupportedStatus("The status %(k)s is not a valid data identifier status." % locals())
        if k == 'open':
            query = query.filter_by(open=True).filter(models.DataIdentifier.type != "file")
            values['open'] = False

    rowcount = query.update(values)

    if not rowcount:
        query = session.query(models.DataIdentifier).filter_by(scope=scope, name=name)
        try:
            query.one()
        except NoResultFound:
            raise exception.DataIdentifierNotFound("Data identifier '%(scope)s:%(name)s' not found" % locals())
        raise exception.UnsupportedOperation("The status of the data identifier '%(scope)s:%(name)s' cannot be changed" % locals())
