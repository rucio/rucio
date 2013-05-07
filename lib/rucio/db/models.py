# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012-2013
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2012
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2013
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013
# - Martin Barisits, <martin.barisits@cern.ch>, 2013

"""
SQLAlchemy models for rucio data
"""

import datetime

from sqlalchemy import BigInteger, Boolean, Column, DateTime, Enum, Integer, String as _String, event, UniqueConstraint
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import object_mapper, relationship, backref
from sqlalchemy.schema import Index, ForeignKeyConstraint, PrimaryKeyConstraint, CheckConstraint, Table
from sqlalchemy.types import LargeBinary

from rucio.common import utils
from rucio.db.constants import AccountStatus, ScopeStatus
from rucio.db.history import Versioned
from rucio.db.session import BASE
from rucio.db.types import GUID


# Recipe to for str instead if unicode
# https://groups.google.com/forum/#!msg/sqlalchemy/8Xn31vBfGKU/bAGLNKapvSMJ
def String(*arg, **kw):
    kw['convert_unicode'] = 'force'
    return _String(*arg, **kw)


class DataIdType:
    FILE = 'file'
    DATASET = 'dataset'
    CONTAINER = 'container'


@compiles(Boolean, "oracle")
def compile_binary_oracle(type_, compiler, **kw):
    return "NUMBER(1)"


@event.listens_for(PrimaryKeyConstraint, "after_parent_attach")
def _pk_constraint_name(const, table):
    const.name = "%s_PK" % (table.name.upper(),)


@event.listens_for(ForeignKeyConstraint, "after_parent_attach")
def _fk_constraint_name(const, table):
    if const.name:
        return
    fk = const.elements[0]
    reftable, refcol = fk.target_fullname.split(".")
    const.name = "fk_%s_%s_%s" % (table.name,
                                  fk.parent.name,
                                  reftable)


@event.listens_for(UniqueConstraint, "after_parent_attach")
def _unique_constraint_name(const, table):
    const.name = "uq_%s_%s" % (table.name, list(const.columns)[0].name)


@event.listens_for(CheckConstraint, "after_parent_attach")
def _ck_constraint_name(const, table):
    if const.name is None:
        if 'DELETED' in str(const.sqltext).upper():
            if len(table.name) > 20:
                const.name = "%s_DEL_CHK" % (table.name.upper())
            else:
                const.name = "%s_DELETED_CHK" % (table.name.upper())
    elif const.name == 'SUBSCRIPTIONS_RETROACTIVE_CHK' and table.name.upper() == 'SUBSCRIPTIONS_HISTORY':
        const.name = "SUBS_HISTORY_RETROACTIVE_CHK"
    elif const.name == 'SUBSCRIPTIONS_STATE_CHK' and table.name.upper() == 'SUBSCRIPTIONS_HISTORY':
        const.name = "SUBS_HISTORY_STATE_CHK"


@event.listens_for(Table, "after_parent_attach")
def _add_created_col(table, metadata):
    if not table.name.upper().endswith('_HISTORY'):
#        table.append_column(Column("created_at", DateTime, default=datetime.datetime.utcnow))
#        table.append_column(Column("updated_at", DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))
        if table.info.get('soft_delete', False):
            table.append_column(Column("deleted", Boolean, default=False))
            table.append_column(Column("deleted_at", DateTime))


class ModelBase(object):
    """Base class for Rucio Models"""
    __table_initialized__ = False

    @declared_attr
    def __table_args__(cls):
        return cls._table_args + (CheckConstraint('"CREATED_AT" IS NOT NULL', name=cls.__tablename__.upper() + '_CREATED_NN'),
                                  CheckConstraint('"UPDATED_AT" IS NOT NULL', name=cls.__tablename__.upper() + '_UPDATED_NN'),
                                  {'mysql_engine': 'InnoDB'})

    @declared_attr
    def created_at(cls):
        return Column("created_at", DateTime, default=datetime.datetime.utcnow)

    @declared_attr
    def updated_at(cls):
        return Column("updated_at", DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    def save(self, flush=True, session=None):
        """Save this object"""
        session.add(self)
        if flush:
            session.flush()

    def delete(self, flush=True, session=None):
        """Delete this object"""
        session.delete(self)
        if flush:
            session.flush()

    def update(self, values, flush=True, session=None):
        """dict.update() behaviour."""
        for k, v in values.iteritems():
            self[k] = v
        if session and flush:
            session.flush()

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __getitem__(self, key):
        return getattr(self, key)

    def __iter__(self):
        self._i = iter(object_mapper(self).columns)
        return self

    def next(self):
        n = self._i.next().name
        return n, getattr(self, n)

    def keys(self):
        return self.__dict__.keys()

    def values(self):
        return self.__dict__.values()

    def items(self):
        return self.__dict__.items()

    def to_dict(self):
        return self.__dict__.copy()


class SoftModelBase(ModelBase):
    """Base class for Rucio Models with soft-deletion support"""
    __table_initialized__ = False

    @declared_attr
    def __table_args__(cls):
        return cls._table_args + (CheckConstraint('"CREATED_AT" IS NOT NULL', name=cls.__tablename__.upper() + '_CREATED_NN'),
                                  CheckConstraint('"UPDATED_AT" IS NOT NULL', name=cls.__tablename__.upper() + '_UPDATED_NN'),
                                  CheckConstraint('DELETED IS NOT NULL', name=cls.__tablename__.upper() + '_DELETED_NN'),
                                  {'mysql_engine': 'InnoDB', 'info': {'soft_delete': True}})

    def delete(self, session=None):
        """Delete this object"""
        self.deleted = True
        self.deleted_at = datetime.datetime.utcnow()
        self.save(session=session)


class Account(BASE, SoftModelBase):
    """Represents an account"""
    __tablename__ = 'accounts'
    account = Column(String(30))
    type = Column(Enum('user', 'group', 'service', name='ACCOUNTS_TYPE_CHK'))
    status = Column(AccountStatus.db_type(default=AccountStatus.ACTIVE, name='ACCOUNTS_STATUS_CHK'))
    suspended_at = Column(DateTime)
    deleted_at = Column(DateTime)
    _table_args = (PrimaryKeyConstraint('account', name='ACCOUNTS_PK'),
                   CheckConstraint('"TYPE" IS NOT NULL', name='ACCOUNTS_TYPE_NN'),
                   CheckConstraint('"STATUS" IS NOT NULL', name='ACCOUNTS_STATUS_NN')
                   )


class Identity(BASE, ModelBase):
    """Represents an identity"""
    __tablename__ = 'identities'
    identity = Column(String(255))
    type = Column(Enum('x509', 'gss', 'userpass', name='IDENTITIES_TYPE_CHK'))  # If you change this, then don't forget to change in the IdentityAccountAssociation as well
    username = Column(String(255))
    password = Column(String(255))
    salt = Column(LargeBinary(255))
    email = Column(String(255))
    _table_args = (PrimaryKeyConstraint('identity', 'type', name='IDENTITIES_PK'),
                   CheckConstraint('"TYPE" IS NOT NULL', name='IDENTITIES_TYPE_NN'),
                   #CheckConstraint('"EMAIL" IS NOT NULL', name='IDENTITIES_EMAIL_NN'),
                   )


class IdentityAccountAssociation(BASE, ModelBase):
    """Represents a map account-identity"""
    __tablename__ = 'account_map'
    identity = Column(String(255))
    type = Column(Enum('x509', 'gss', 'userpass', name='ACCOUNT_MAP_TYPE_CHK'))
    account = Column(String(30))
    is_default = Column(Boolean(name='ACCOUNT_MAP_DEFAULT_CHK'), default=False)
    _table_args = (PrimaryKeyConstraint('identity', 'type', 'account', name='ACCOUNT_MAP_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='ACCOUNT_MAP_ACCOUNT_FK'),
                   ForeignKeyConstraint(['identity', 'type'], ['identities.identity', 'identities.type'], name='ACCOUNT_MAP_ID_TYPE_FK'),
                   CheckConstraint('is_default IS NOT NULL', name='ACCOUNT_MAP_IS_DEFAULT_NN'),
                   CheckConstraint('"TYPE" IS NOT NULL', name='ACCOUNT_MAP_TYPE_NN'),
                   )


class Scope(BASE, ModelBase):
    """Represents a scope"""
    __tablename__ = 'scopes'
    scope = Column(String(30))
    account = Column(String(30))
    is_default = Column(Boolean(name='SCOPES_DEFAULT_CHK'), default=0)
    status = Column(ScopeStatus.db_type(name='SCOPE_STATUS_CHK', default=ScopeStatus.OPEN))
    closed_at = Column(DateTime)
    deleted_at = Column(DateTime)
    _table_args = (PrimaryKeyConstraint('scope', name='SCOPES_SCOPE_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='SCOPES_ACCOUNT_FK'),
                   CheckConstraint('is_default IS NOT NULL', name='SCOPES_IS_DEFAULT_NN'),
                   CheckConstraint('STATUS IS NOT NULL', name='SCOPES_STATUS_NN'),
                   CheckConstraint('account IS NOT NULL', name='SCOPES_ACCOUNT_NN')
                   )


class DataIdentifier(BASE, SoftModelBase):
    """Represents a dataset"""
    __tablename__ = 'dids'
    scope = Column(String(30))
    name = Column(String(255))
    account = Column(String(30))
    type = Column(Enum('file', 'dataset', 'container', name='DIDS_TYPE_CHK'))
    open = Column(Boolean(name='DIDS_OPEN_CHK'))
    monotonic = Column(Boolean(name='DIDS_MONOTONIC_CHK'), server_default='0')
    hidden = Column(Boolean(name='DIDS_HIDDEN_CHK'), server_default='0')
    obsolete = Column(Boolean(name='DIDS_OBSOLETE_CHK'), server_default='0')
    complete = Column(Boolean(name='DIDS_COMPLETE_CHK'))
    new = Column(Boolean(name='DIDS_NEW_CHK'), server_default='1')
    availability = Column(Enum('lost', 'deleted', 'available', name='DIDS_AVAILABILITY_CHK'))
    suppressed = Column(Boolean(name='FILES_SUPP_CHK'), server_default='0')
    size = Column(BigInteger)
    md5 = Column(String(32))
    adler32 = Column(String(8))
    guid = Column(GUID())
    expired_at = Column(DateTime)
    _table_args = (PrimaryKeyConstraint('scope', 'name', name='DIDS_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], ondelete='CASCADE', name='DIDS_ACCOUNT_FK'),
                   ForeignKeyConstraint(['scope'], ['scopes.scope'], name='DIDS_SCOPE_FK'),
                   CheckConstraint('"MONOTONIC" IS NOT NULL', name='DIDS_MONOTONIC_NN'),
                   CheckConstraint('"OBSOLETE" IS NOT NULL', name='DIDS_OBSOLETE_NN'),
                   CheckConstraint('"SUPPRESSED" IS NOT NULL', name='DIDS_SUPP_NN'),
                   UniqueConstraint('guid', name='DIDS_GUID_UQ'),
                   Index('DIDS_NEW_IDX', 'new'),
                   Index('DIDS_EXPIRED_AT', 'expired_at')
                   )


class DIDKey(BASE, ModelBase):
    """Represents Data IDentifier property keys"""
    __tablename__ = 'did_keys'
    key = Column(String(255))
    key_type = Column(Enum('all', 'collection', 'file', 'derived', name='DID_KEYS_KEY_TYPE_CHK'))
    value_type = Column(String(255))
    value_regexp = Column(String(255))
    _table_args = (PrimaryKeyConstraint('key', name='DID_KEYS_PK'),
                   CheckConstraint('key_type IS NOT NULL', name='DID_KEYS_KEY_TYPE_NN'),
                   )


class DIDKeyValueAssociation(BASE, ModelBase):
    """Represents Data IDentifier property key/values"""
    __tablename__ = 'did_key_map'
    key = Column(String(255))
    value = Column(String(255))
    _table_args = (PrimaryKeyConstraint('key', 'value', name='DID_KEY_MAP_PK'),
                   ForeignKeyConstraint(['key'], ['did_keys.key'], name='DID_MAP_KEYS_FK'),)


class DIDAttribute(BASE, ModelBase):
    """Represents Data IDentifier  properties"""
    __tablename__ = 'did_attributes'
    scope = Column(String(30))
    name = Column(String(255))
    key = Column(String(255))
    value = Column(String(255))
    _table_args = (PrimaryKeyConstraint('scope', 'name', 'key', name='DID_ATTR_PK'),
                   ForeignKeyConstraint(['scope', 'name'], ['dids.scope', 'dids.name'], name='DID_ATTR_SCOPE_NAME_FK'),
                   ForeignKeyConstraint(['scope'], ['scopes.scope'], name='DID_ATTR_SCOPE_FK'),
                   ForeignKeyConstraint(['key'], ['did_keys.key'], name='DID_ATTR_KEYS_FK'),
                   Index('DID_ATTR_KEY_IDX', 'key'),)


class DataIdentifierAssociation(BASE, ModelBase):
    """Represents the map between containers/datasets and files"""
    __tablename__ = 'contents'
    scope = Column(String(30))         # dataset scope
    name = Column(String(255))          # dataset name
    child_scope = Column(String(30))   # Provenance scope
    child_name = Column(String(255))    # Provenance name
    type = Column(Enum('file', 'dataset', 'container', name='CONTENTS_TYPE_CHK'))
    child_type = Column(Enum('file', 'dataset', 'container', name='CONTENTS_CHILD_TYPE_CHK'))
    size = Column(BigInteger)
    adler32 = Column(String(8))
    md5 = Column(String(32))
    _table_args = (PrimaryKeyConstraint('scope', 'name', 'child_scope', 'child_name', name='CONTENTS_PK'),
                   ForeignKeyConstraint(['scope', 'name'], ['dids.scope', 'dids.name'], name='CONTENTS_ID_FK'),
                   ForeignKeyConstraint(['child_scope', 'child_name'], ['dids.scope', 'dids.name'], ondelete="CASCADE", name='CONTENTS_CHILD_ID_FK'),
                   CheckConstraint('"TYPE" IS NOT NULL', name='CONTENTS_TYPE_NN'),
                   CheckConstraint('"CHILD_TYPE" IS NOT NULL', name='CONTENTS_CHILD_TYPE_NN'),
                   Index('CONTENTS_CHILD_SCOPE_NAME_IDX', 'child_scope', 'child_name'),)


class RSE(BASE, SoftModelBase):
    """Represents a Rucio Location"""
    __tablename__ = 'rses'
    id = Column(GUID(), default=utils.generate_uuid)
    rse = Column(String(255))
    type = Column(Enum('disk', 'tape', name='RSES_TYPE_CHK'), default='disk')
    prefix = Column(String(1024))
    deterministic = Column(Boolean(name='RSE_DETERMINISTIC_CHK'), default=True)
    volatile = Column(Boolean(name='RSE_VOLATILE_CHK'), default=False)
    usage = relationship("RSEUsage", order_by="RSEUsage.rse_id", backref="rses")
#    replicas = relationship("RSEFileAssociation", order_by="RSEFileAssociation.rse_id", backref="rses")
    _table_args = (PrimaryKeyConstraint('id', name='RSES_PK'),
                   UniqueConstraint('rse', name='RSES_RSE_UQ'),
                   CheckConstraint('"RSE" IS NOT NULL', name='RSES_RSE__NN'),
                   CheckConstraint('"TYPE" IS NOT NULL', name='RSES_TYPE_NN'), )


class RSELimit(BASE, ModelBase):
    """Represents RSE limits"""
    __tablename__ = 'rse_limits'
    rse_id = Column(GUID())
    name = Column(String(255))
    value = Column(BigInteger)
    _table_args = (PrimaryKeyConstraint('rse_id', 'name', name='RSE_LIMITS_PK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='RSE_LIMIT_RSE_ID_FK'), )


class RSEUsage(BASE, ModelBase, Versioned):
    """Represents location usage"""
    __tablename__ = 'rse_usage'
    rse_id = Column(GUID())
    source = Column(String(255))
    used = Column(BigInteger)
    free = Column(BigInteger)
    rse = relationship("RSE", backref=backref('rse_usage', order_by=rse_id))
    _table_args = (PrimaryKeyConstraint('rse_id', 'source', name='RSE_USAGE_PK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='RSE_USAGE_RSE_ID_FK'), )


class RSEAttrAssociation(BASE, ModelBase):
    """Represents the map between RSEs and tags"""
    __tablename__ = 'rse_attr_map'
    rse_id = Column(GUID())
    key = Column(String(255))
    value = Column(String(255))
    rse = relationship("RSE", backref=backref('rse_attr_map', order_by=rse_id))
    _table_args = (PrimaryKeyConstraint('rse_id', 'key', name='RSE_ATTR_MAP_PK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='RSE_ATTR_MAP_RSE_ID_FK'), )


class RSEProtocols(BASE, ModelBase):
    """Represents supported protocols of RSEs (Rucio Storage Elements)"""
    __tablename__ = 'rse_protocols'
    rse_id = Column(GUID())
    scheme = Column(String(255))
    hostname = Column(String(255), default='')  # For protocol without host e.g. POSIX on local file systems localhost is assumed as beeing default
    port = Column(Integer, default=0)  # like host, for local protocol the port 0 is assumed to be default
    prefix = Column(String(1024), nullable=True)
    impl = Column(String(255), nullable=False)
    read_LAN = Column(Integer, default=0)  # if no value is provided, 0 i.e. not supported is assumed as default value
    write_LAN = Column(Integer, default=0)  # if no value is provided, 0 i.e. not supported is assumed as default value
    delete_LAN = Column(Integer, default=0)  # if no value is provided, 0 i.e. not supported is assumed as default value
    read_WAN = Column(Integer, default=0)  # if no value is provided, 0 i.e. not supported is assumed as default value
    write_WAN = Column(Integer, default=0)  # if no value is provided, 0 i.e. not supported is assumed as default value
    delete_WAN = Column(Integer, default=0)  # if no value is provided, 0 i.e. not supported is assumed as default value
    extended_attributes = Column(String(1024), nullable=True)
    rses = relationship("RSE", backref="rse_protocols")
    _table_args = (PrimaryKeyConstraint('rse_id', 'scheme', 'hostname', 'port', name='RSE_PROTOCOL_PK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='RSE_PROTOCOL_RSE_ID_FK'),
                   CheckConstraint('"IMPL" IS NOT NULL', name='RSE_PROTOCOLS_IMPL_NN'),
                   )


class AccountLimit(BASE, ModelBase):
    """Represents account limits"""
    __tablename__ = 'account_limits'
    account = Column(String(30))
    rse_expression = Column(String(255))
    name = Column(String(255))
    value = Column(BigInteger)
    _table_args = (PrimaryKeyConstraint('account', 'rse_expression', 'name', name='ACCOUNT_LIMITS_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='ACCOUNT_LIMITS_ACCOUNT_FK'))


class AccountUsage(BASE, ModelBase, Versioned):
    """Represents account usage"""
    __tablename__ = 'account_usage'
    account = Column(String(30))
    rse_id = Column(GUID())
    name = Column(String(255))
    value = Column(BigInteger)
    _table_args = (PrimaryKeyConstraint('account', 'rse_id', 'name', name='ACCOUNT_USAGE_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='ACCOUNT_USAGE_ACCOUNT_FK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='ACCOUNT_USAGE_RSES_ID_FK'), )


class RSEFileAssociation(BASE, ModelBase):
    """Represents the map between locations and files"""
    __tablename__ = 'replicas'
    rse_id = Column(GUID())
    scope = Column(String(30))
    name = Column(String(255))
    size = Column(BigInteger)
    md5 = Column(String(32))
    adler32 = Column(String(8))
    path = Column(String(1024))
    state = Column(Enum('AVAILABLE', 'UNAVAILABLE', 'COPYING', 'BAD', name='REPLICAS_STATE_CHK'), default='UNAVAILABLE')
    lock_cnt = Column(Integer, default=0)
    accessed_at = Column(DateTime)
    tombstone = Column(DateTime)
    rse = relationship("RSE", backref=backref('replicas', order_by="RSE.id"))
    _table_args = (PrimaryKeyConstraint('rse_id', 'scope', 'name', name='REPLICAS_PK'),
                   ForeignKeyConstraint(['scope', 'name'], ['dids.scope', 'dids.name'], name='REPLICAS_LFN_FK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='REPLICAS_RSE_ID_FK'),
                   CheckConstraint('"STATE" IS NOT NULL', name='REPLICAS_STATE_NN'),
                   Index('REPLICAS_TOMBSTONE_IDX', 'tombstone'),
                   )
#                   ForeignKeyConstraint(['rse_id', 'scope', 'name'], ['replica_locks.rse_id', 'replica_locks.scope', 'replica_locks.name'], name='REPLICAS_RULES_FK'),


class ReplicationRule(BASE, ModelBase):
    """Represents data identifier replication rules"""
    __tablename__ = 'rules'
    id = Column(GUID(), default=utils.generate_uuid)
    subscription_id = Column(GUID())
    account = Column(String(30))
    scope = Column(String(30))
    name = Column(String(255))
    state = Column(Enum('REPLICATING', 'OK', 'STUCK', 'SUSPENDED', name='RULES_STATE_CHK'), default='REPLICATING')
    rse_expression = Column(String(255))
    copies = Column(Integer(), default=1)
    expires_at = Column(DateTime)
    weight = Column(String(255))
    locked = Column(Boolean(name='RULES_LOCKED_CHK'), default=False)
    grouping = Column(Enum('ALL', 'DATASET', 'NONE', name='RULES_GROUPING_CHK'), default="ALL")
    _table_args = (PrimaryKeyConstraint('id', name='RULES_PK'),
                   ForeignKeyConstraint(['scope', 'name'], ['dids.scope', 'dids.name'], name='RULES_SCOPE_NAME_FK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='RULES_ACCOUNT_FK'),
                   ForeignKeyConstraint(['subscription_id'], ['subscriptions.id'], name='RULES_SUBS_ID_FK'),
                   CheckConstraint('"STATE" IS NOT NULL', name='RULES_STATE_NN'),
                   CheckConstraint('"GROUPING" IS NOT NULL', name='RULES_GROUPING_NN'),
                   CheckConstraint('"COPIES" IS NOT NULL', name='RULES_COPIES_NN'),
                   CheckConstraint('"LOCKED" IS NOT NULL', name='RULES_LOCKED_NN'),
                   UniqueConstraint('scope', 'name', 'account', 'rse_expression', 'copies', name='RULES_UQ'),)


class ReplicaLock(BASE, ModelBase):
    """Represents replica locks"""
    __tablename__ = 'locks'
    scope = Column(String(30))
    name = Column(String(255))
    rule_id = Column(GUID())
    rse_id = Column(GUID())
    account = Column(String(30))
    size = Column(BigInteger)
    state = Column(Enum('REPLICATING', 'OK', 'STUCK', name='LOCKS_STATE_CHK'), default='REPLICATING')
    _table_args = (PrimaryKeyConstraint('scope', 'name', 'rule_id', 'rse_id', name='LOCKS_PK'),
                   ForeignKeyConstraint(['scope', 'name'], ['dids.scope', 'dids.name'], name='LOCKS_DID_FK'),
                   ForeignKeyConstraint(['rule_id'], ['rules.id'], name='LOCKS_RULE_ID_FK', ondelete='CASCADE'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='LOCKS_ACCOUNT_FK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='LOCKS_RSES_FK'),
                   CheckConstraint('"STATE" IS NOT NULL', name='LOCKS_STATE_NN'),
                   Index('LOCKS_RULE_ID_IDX', 'rule_id'),
                   Index('LOCKS_ACCOUNT_RSE_ID_IDX', 'account', 'rse_id')  # Needed for accounting?
                   )


class Request(BASE, ModelBase):
    """Represents a request for a single file with a third party service"""
    __tablename__ = 'requests'
    id = Column(GUID(), default=utils.generate_uuid)
    type = Column(Enum('TRANSFER', 'DELETE', 'UPLOAD', 'DOWNLOAD', name='REQUESTS_TYPE_CHK'), default='TRANSFER')
    scope = Column(String(30))
    name = Column(String(255))
    dest_rse_id = Column(GUID())
    attributes = Column(String(4000))
    state = Column(Enum('QUEUED', 'SUBMITTED', 'FAILED', 'DONE', name='REQUESTS_STATE_CHK'), default='QUEUED')
    external_id = Column(String(64))
    retry_count = Column(Integer(), default=0)
    err_msg = Column(String(4000))
    previous_attempt_id = Column(GUID())
    _table_args = (PrimaryKeyConstraint('scope', 'name', 'dest_rse_id', name='REQUESTS_PK'),
                   ForeignKeyConstraint(['scope', 'name'], ['dids.scope', 'dids.name'], name='REQUESTS_DID_FK'),
                   ForeignKeyConstraint(['dest_rse_id'], ['rses.id'], name='REQUESTS_RSES_FK'),
                   Index('REQUESTS_ID_IDX', 'id'),
                   Index('REQUESTS_TYPE_STATE_IDX', 'type', 'state')
                   )


class Subscription(BASE, ModelBase, Versioned):
    """Represents a subscription"""
    __tablename__ = 'subscriptions'
    id = Column(GUID(), default=utils.generate_uuid)
    name = Column(String(64))
    filter = Column(String(2048))
    replication_rules = Column(String(1024))
    policyid = Column(Integer(), default=0)
    state = Column(Enum('ACTIVE', 'INACTIVE', 'NEW', 'UPDATED', 'BROKEN', name='SUBSCRIPTIONS_STATE_CHK'), default='ACTIVE')
    last_processed = Column(DateTime, default=datetime.datetime.utcnow())
    account = Column(String(255))
    #issuer = Column(String(255))
    lifetime = Column(DateTime, default=datetime.datetime(4772, 10, 13))  # default lifetime is till the End of the Maya Long Count Calendar
    retroactive = Column(Boolean(name='SUBSCRIPTIONS_RETROACTIVE_CHK'), default=False)
    expired_at = Column(DateTime)
    _table_args = (PrimaryKeyConstraint('id', name='SUBSCRIPTIONS_PK'),
                   UniqueConstraint('name', 'account', name='SUBSCRIPTION_NAME_ACCOUNT_UQ'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='SUBSCRIPTIONS_ACCOUNT_FK'),
                   CheckConstraint('"RETROACTIVE" IS NOT NULL', name='SUBSCRIPTIONS_RETROACTIVE_NN'),)


class Token(BASE, ModelBase):
    """Represents the authentication tokens and their lifetime"""
    __tablename__ = 'tokens'
    token = Column(String(352))  # account-identity-appid-uuid -> max length: (+ 30 1 255 1 32 1 32)
    account = Column(String(30))
    expired_at = Column(DateTime, default=lambda: datetime.datetime.utcnow() + datetime.timedelta(seconds=3600))  # one hour lifetime by default
    ip = Column(String(39), nullable=True)
    _table_args = (PrimaryKeyConstraint('account', 'token', name='TOKENS_TOKEN_ACCOUNT_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='TOKENS_ACCOUNT_FK'),
                   CheckConstraint('"EXPIRED_AT" IS NOT NULL', name='TOKENS_EXPIRED_AT_NN'),)


class Callback(BASE, ModelBase):
    """Represents the event callbacks"""
    __tablename__ = 'callbacks'
    id = Column(GUID(), default=utils.generate_uuid)
    event_type = Column(String(1024))
    payload = Column(String(4000))
    _table_args = (PrimaryKeyConstraint('id', name='CALLBACKS_ID_PK'),
                   CheckConstraint('"EVENT_TYPE" IS NOT NULL', name='CALLBACKS_EVENT_TYPE_NN'),
                   CheckConstraint('"PAYLOAD" IS NOT NULL', name='CALLBACKS_PAYLOAD_NN'),)


def register_models(engine):
    """
    Creates database tables for all models with the given engine
    """
    models = (Account,
              AccountLimit,
              AccountUsage,
              Callback,
              DIDAttribute,
              DIDKey,
              DIDKeyValueAssociation,
              DataIdentifier,
              Identity,
              IdentityAccountAssociation,
              RSE,
              RSEAttrAssociation,
              RSEFileAssociation,
              RSELimit,
              RSEProtocols,
              RSEUsage,
              ReplicationRule,
              ReplicaLock,
              ReplicationRule,
              Request,
              Scope,
              Subscription,
              Token)

    for model in models:
        model.metadata.create_all(engine)


def unregister_models(engine):
    """
    Drops database tables for all models with the given engine
    """
    models = (Account,
              AccountLimit,
              AccountUsage,
              Callback,
              DIDAttribute,
              DIDKey,
              DIDKeyValueAssociation,
              DataIdentifier,
              Identity,
              IdentityAccountAssociation,
              RSE,
              RSEAttrAssociation,
              RSEFileAssociation,
              RSELimit,
              RSEProtocols,
              RSEUsage,
              ReplicationRule,
              ReplicaLock,
              ReplicationRule,
              Request,
              Scope,
              Subscription,
              Token)

    for model in models:
        model.metadata.drop_all(engine)
