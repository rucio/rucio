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

"""
SQLAlchemy models for rucio data
"""

import datetime

from uuid import uuid4 as uuid

from sqlalchemy import BigInteger, Boolean, Column, DateTime, Integer, String
from sqlalchemy import event
from sqlalchemy import UniqueConstraint
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import object_mapper, relationship, backref
from sqlalchemy.schema import Index, ForeignKeyConstraint, PrimaryKeyConstraint, CheckConstraint, Table
from sqlalchemy.types import LargeBinary

from rucio.common import utils
from rucio.db.history import Versioned
from rucio.db.session import BASE
from rucio.db.types import GUID


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


@event.listens_for(Table, "after_parent_attach")
def _add_created_col(table, metadata):
    if not table.name.upper().endswith('_HISTORY'):
        table.append_column(Column("created_at", DateTime, default=datetime.datetime.utcnow))
        table.append_column(Column("updated_at", DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))
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

    def save(self, session=None):
        """Save this object"""
        session.add(self)
        session.flush()

    def delete(self, soft=True, session=None):
        """Delete this object"""
        session.delete(self)
        session.flush()

    def update(self, values):
        """dict.update() behaviour."""
        for k, v in values.iteritems():
            self[k] = v

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


class Account(BASE,  SoftModelBase):
    """Represents an account"""
    __tablename__ = 'accounts'
    account = Column(String(30))
    type = Column(String(10))
    status = Column(String(10))
    _table_args = (PrimaryKeyConstraint('account', name='ACCOUNTS_PK'),
                   CheckConstraint("type IN ('user', 'group', 'service')", name='ACCOUNTS_TYPE_CHK'),
                   CheckConstraint("status IN ('active', 'inactive', 'disabled')", name='ACCOUNTS_STATUS_CHK'),
                   CheckConstraint('"TYPE" IS NOT NULL', name='ACCOUNT_TYPE_NN'),
                   CheckConstraint('"STATUS" IS NOT NULL', name='ACCOUNT_STATUS_NN')
                   )


class Identity(BASE, ModelBase):
    """Represents an identity"""
    __tablename__ = 'identities'
    identity = Column(String(255))
    type = Column(String(8))
    username = Column(String(255))
    password = Column(String(255))
    salt = Column(LargeBinary(255))
    email = Column(String(255))
    _table_args = (PrimaryKeyConstraint('identity', 'type', name='IDENTITIES_PK'),
                   CheckConstraint("type IN ('x509', 'gss', 'userpass')", name='IDENTITIES_TYPE_CHK'),  # If you change this, then don't forget to change in the IdentityAccountAssociation as well
                   #CheckConstraint('"EMAIL" IS NOT NULL', name='IDENTITIES_EMAIL_NN'),
                   )


class IdentityAccountAssociation(BASE, ModelBase):
    """Represents a map account-identity"""
    __tablename__ = 'account_map'
    identity = Column(String(255))
    type = Column(String(8))
    account = Column(String(30))
    is_default = Column(Boolean(name='ACCOUNT_MAP_DEFAULT_CHK'), default=False)
    _table_args = (PrimaryKeyConstraint('identity', 'type', 'account', name='ACCOUNT_MAP_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='ACCOUNT_MAP_ACCOUNT_FK'),
                   ForeignKeyConstraint(['identity', 'type'], ['identities.identity', 'identities.type'], name='ACCOUNT_MAP_ID_TYPE_FK'),
                   CheckConstraint("type IN ('x509', 'gss', 'userpass')", name='ACCOUNT_MAP_TYPE_CHK'),
                   CheckConstraint('is_default IS NOT NULL', name='ACCOUNT_MAP_IS_DEFAULT_NN'),)


class Scope(BASE, SoftModelBase):
    """Represents a scope"""
    __tablename__ = 'scopes'
    scope = Column(String(30))
    account = Column(String(30))
    is_default = Column(Boolean(name='SCOPES_DEFAULT_CHK'), default=0)
    _table_args = (PrimaryKeyConstraint('scope', name='SCOPES_SCOPE_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='SCOPES_ACCOUNT_FK'),
                   CheckConstraint('is_default IS NOT NULL', name='SCOPES_IS_DEFAULT_NN'),
                   CheckConstraint('account IS NOT NULL', name='SCOPES_ACCOUNT_NN')
                   )


class DataIdentifier(BASE, SoftModelBase):
    """Represents a dataset"""
    __tablename__ = 'dids'
    scope = Column(String(30))
    name = Column(String(255))
    owner = Column(String(255))
    type = Column(String(9))
    open = Column(Boolean(name='DIDS_OPEN_CHK'))
    monotonic = Column(Boolean(name='DIDS_MONOTONIC_CHK'), server_default='0')
    hidden = Column(Boolean(name='DIDS_HIDDEN_CHK'), server_default='0')
    obsolete = Column(Boolean(name='DIDS_OBSOLETE_CHK'), server_default='0')
    complete = Column(Boolean(name='DIDS_COMPLETE_CHK'))
    _table_args = (PrimaryKeyConstraint('scope', 'name', name='DIDS_PK'),
                   ForeignKeyConstraint(['owner'], ['accounts.account'], ondelete='CASCADE', name='DIDS_ACCOUNT_FK'),
                   ForeignKeyConstraint(['scope'], ['scopes.scope'], name='DIDS_SCOPE_FK'),
                   CheckConstraint('"MONOTONIC" IS NOT NULL', name='DIDS_MONOTONIC_NN'),
                   CheckConstraint('"OBSOLETE" IS NOT NULL', name='DIDS_OBSOLETE_NN'),
                   CheckConstraint("TYPE IN ('file', 'dataset', 'container')", name='DIDS_TYPE_CHK'),)


class File(BASE, SoftModelBase):
    """Represents a file"""
    __tablename__ = 'files'
    scope = Column(String(30))
    name = Column(String(255))
    owner = Column(String(255))
    availability = Column(String(32))
    suppressed = Column(Boolean(name='FILES_SUPP_CHK'), server_default='0')
    size = Column(BigInteger)
    checksum = Column(String(32))
    guid = Column(GUID())
    _table_args = (PrimaryKeyConstraint('scope', 'name', name='FILES_PK'),
                   ForeignKeyConstraint(['owner'], ['accounts.account'], ondelete='CASCADE', name='FILES_ACCOUNT_FK'),
                   ForeignKeyConstraint(['scope', 'name'], ['dids.scope', 'dids.name'], name='FILES_DATA_ID_FK', ondelete="CASCADE"),
                   ForeignKeyConstraint(['scope'], ['scopes.scope'], name='FILES_SCOPE_FK'),
                   CheckConstraint("availability IN ('lost', 'deleted', 'available')", name='DATA_ID_TYPE_CHK'),
                   CheckConstraint('"SUPPRESSED" IS NOT NULL', name='FILES_SUPP_NN'),
                   UniqueConstraint('guid', name='FILES_GUID_UQ'),)


class DIDKey(BASE, ModelBase):
    """Represents Data IDentifier property keys"""
    __tablename__ = 'did_keys'
    key = Column(String(255))
    key_type = Column(String(255))
    value_type = Column(String(255))
    value_regexp = Column(String(255))
    _table_args = (PrimaryKeyConstraint('key', name='DID_KEYS_PK'),
                   CheckConstraint('key_type IS NOT NULL', name='DID_KEYS_KEY_TYPE_NN'),
                   CheckConstraint("key_type IN ('all', 'collection', 'file', 'derived')", name='DID_KEYS_KEY_TYPE_CHK'),)


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
    type = Column(String(9))
    child_type = Column(String(9))
    _table_args = (PrimaryKeyConstraint('scope', 'name', 'child_scope', 'child_name', name='CONTENTS_PK'),
                   ForeignKeyConstraint(['scope', 'name'], ['dids.scope', 'dids.name'], name='CONTENTS_ID_FK'),
                   ForeignKeyConstraint(['child_scope', 'child_name'], ['dids.scope', 'dids.name'], ondelete="CASCADE", name='CONTENTS_CHILD_ID_FK'),
                   CheckConstraint("type IN ('file', 'dataset', 'container')", name='CONTENTS_TYPE_CHK'),
                   CheckConstraint("child_type IN ('file', 'dataset', 'container')", name='CONTENTS_CHILD_TYPE_CHK'),
                   Index('CONTENTS_CHILD_SCOPE_NAME_IDX', 'child_scope', 'child_name'),)


class RSE(BASE, SoftModelBase):
    """Represents a Rucio Location"""
    __tablename__ = 'rses'
    id = Column(GUID(), default=lambda: str(uuid()))
    rse = Column(String(255))
    type = Column(String(255), default='disk')
    prefix = Column(String(1024))
    deterministic = Column(Boolean(name='RSE_DETERMINISTIC_CHK'), default=True)
    volatile = Column(Boolean(name='RSE_VOLATILE_CHK'), default=False)
    usage = relationship("RSEUsage", order_by="RSEUsage.rse_id", backref="rses")
#    file_replicas = relationship("RSEFileAssociation", order_by="RSEFileAssociation.rse_id", backref="rses")
    _table_args = (PrimaryKeyConstraint('id', name='RSES_PK'),
                   UniqueConstraint('rse', name='RSES_RSE_UQ'),
                   CheckConstraint('"RSE" IS NOT NULL', name='RSES_RSE__NN'),
                   CheckConstraint("type IN ('disk','tape')", name='RSES_TYPE_CHK'),)


class RSEUsage(BASE, ModelBase, Versioned):
    """Represents location usage"""
    __tablename__ = 'rse_usage'
    rse_id = Column(GUID())
    source = Column(String(255))
    total = Column(BigInteger)
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
    protocol = Column(String(255))
    hostname = Column(String(255), default='localhost')  # For protocol without host e.g. POSIX on local file systems localhost is assumed as beeing default
    port = Column(Integer, default=0)  # like host, for local protocol the port 0 is assumed to be default
    prefix = Column(String(1024), nullable=True)
    impl = Column(String(255), nullable=False)
    read = Column(Integer, default=-1)  # if no value is provided, -1 i.e. not supported is assumed as default value
    write = Column(Integer, default=-1)  # if no value is provided, -1 i.e. not supported is assumed as default value
    delete = Column(Integer, default=-1)  # if no value is provided, -1 i.e. not supported is assumed as default value
    extended_attributes = Column(String(1024), nullable=True)
    rses = relationship("RSE", backref="rse_protocols")
    _table_args = (PrimaryKeyConstraint('rse_id', 'protocol', 'hostname', 'port', name='RSE_PROTOCOL_PK'),
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
    __tablename__ = 'file_replicas'
    rse_id = Column(GUID())
    scope = Column(String(30))
    name = Column(String(255))
    size = Column(BigInteger)
    checksum = Column(String(32))
    path = Column(String(1024))
    state = Column(String(255), default='UNAVAILABLE')
    rse = relationship("RSE", backref=backref('file_replicas', order_by="RSE.id"))
    _table_args = (PrimaryKeyConstraint('rse_id', 'scope', 'name', name='FILE_REPLICAS_PK'),
                   ForeignKeyConstraint(['scope', 'name'], ['files.scope', 'files.name'], name='FILE_REPLICAS_LFN_FK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='FILE_REPLICAS_RSE_ID_FK'),
                   CheckConstraint("state IN ('AVAILABLE', 'UNAVAILABLE', 'COPYING', 'BAD')", name='FILE_REPLICAS_STATE_CHK'),)
#                   ForeignKeyConstraint(['rse_id', 'scope', 'name'], ['replica_locks.rse_id', 'replica_locks.scope', 'replica_locks.name'], name='FILE_REPLICAS_RULE_FK'),


class ReplicationRule(BASE, ModelBase):
    """Represents data identifier replication rules"""
    __tablename__ = 'did_rules'
    id = Column(GUID(), default=utils.generate_uuid)
    account = Column(String(30))
    state = Column(String(255), default='waiting')
    scope = Column(String(30))
    name = Column(String(255))
    rse_expression = Column(String(255))
    rses = Column(String(255))
    copies = Column(Integer(), default=1)
    expired_at = Column(DateTime)
    locked = Column(Boolean(name='FILE_RULES_LOCKED_CHK'), default=False)
    grouping = Column(Boolean(name='FILE_RULES_GROUPING_CHK'), default=False)

    _table_args = (PrimaryKeyConstraint('scope', 'name', 'id', name='DID_RULES_PK'),
                   ForeignKeyConstraint(['scope', 'name'], ['dids.scope', 'dids.name'], name='DID_RULES_SCOPE_NAME_FK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='DID_RULES_ACCOUNT_FK'),
                   CheckConstraint('"STATE" IS NOT NULL', name='DID_RULES_STATE_NN'),
                   CheckConstraint('"COPIES" IS NOT NULL', name='DID_RULES_COPIES_NN'),
                   CheckConstraint('"LOCKED" IS NOT NULL', name='DID_RULES_LOCKED_NN'),)
#                   ForeignKeyConstraint(['account', 'rse_tag_id', 'parent_scope', 'parent_dsn'],
#                   ['dataset_rules.account', 'dataset_rules.rse_tag_id', 'dataset_rules.scope', 'dataset_rules.dsn'],
#                   name='FILE_DATASET_RULES_FK'),


class ReplicaLock(BASE, ModelBase):
    """Represents replica locks"""
    __tablename__ = 'replica_locks'
    rse_id = Column(GUID())
    rule_id = Column(GUID())
    scope = Column(String(30))
    name = Column(String(255))
    account = Column(String(30))
    # type = Column(String(9)) Duplication of the type for partionning ?
    _table_args = (PrimaryKeyConstraint('rule_id', 'rse_id', 'scope', 'name', name='REPLICA_LOCKS_PK'),
                   ForeignKeyConstraint(['scope', 'name'], ['dids.scope', 'dids.name'], name='REPLICAS_DID_FK'),
                   # ForeignKeyConstraint(['rule_id', 'scope', 'name'], ['did_rules.id', 'did_rules.scope', 'did_rules.name'], name='REPLICAS_LOCKS_RULE_ID_FK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='REPLICA_LOCKS_ACCOUNT_FK'),
                   )


class Subscription(BASE, ModelBase):
    """Represents a subscription"""
    __tablename__ = 'subscriptions'
    id = Column(GUID(), default=utils.generate_uuid)
    account = Column(String(30))
    retroactive = Column(Boolean(name='SUBSCRIPTIONS_RETROACTIVE_CHK'), default=False)
    expired_at = Column(DateTime)
    _table_args = (PrimaryKeyConstraint('id', 'account', name='SUBSCRIPTIONS_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='SUBSCRIPTIONS_ACCOUNT_FK'),
                   CheckConstraint('"RETROACTIVE" IS NOT NULL', name='SUBSCRIPTIONS_RETROACTIVE_NN'),)


class Authentication(BASE, ModelBase):
    """Represents the authentication tokens and their lifetime"""
    __tablename__ = 'authentication'
    token = Column(String(352))  # account-identity-appid-uuid -> max length: (+ 30 1 255 1 32 1 32)
    account = Column(String(30))
    lifetime = Column(DateTime, default=lambda: datetime.datetime.utcnow() + datetime.timedelta(seconds=3600))  # one hour lifetime by default
    ip = Column(String(16), nullable=True)
    _table_args = (PrimaryKeyConstraint('token', 'account', name='AUTH_TOKEN_ACCOUNT_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='AUTH_ACCOUNT_FK'),
                   CheckConstraint('"LIFETIME" IS NOT NULL', name='AUTH_LIFETIME_NN'),)


def register_models(engine):
    """
    Creates database tables for all models with the given engine
    """
    models = (Account,
              Identity,
              IdentityAccountAssociation,
              Scope,
              DataIdentifier,
              File,
              DIDKey,
              DIDKeyValueAssociation,
              DIDAttribute,
              RSE,
              RSEUsage,
              RSEProtocols,
              AccountLimit,
              AccountUsage,
              RSEAttrAssociation,
              RSEFileAssociation,
              ReplicationRule,
              ReplicaLock,
              Subscription,
              Authentication)
    for model in models:
        model.metadata.create_all(engine)


def unregister_models(engine):
    """
    Drops database tables for all models with the given engine
    """
    models = (Account,
              Identity,
              IdentityAccountAssociation,
              Scope,
              DataIdentifier,
              DIDKey,
              DIDKeyValueAssociation,
              DIDAttribute,
              File,
              RSE,
              RSEProtocols,
              RSEUsage,
              AccountLimit,
              AccountUsage,
              RSEAttrAssociation,
              RSEFileAssociation,
              ReplicationRule,
              ReplicaLock,
              Subscription,
              Authentication)

    for model in models:
        model.metadata.drop_all(engine)
