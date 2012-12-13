# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2012

"""
SQLAlchemy models for rucio data
"""

import datetime

from sqlalchemy import BigInteger, Boolean, Column, DateTime, Integer, String, Text
from sqlalchemy import event
from sqlalchemy import UniqueConstraint
from sqlalchemy.ext.declarative import declared_attr, declarative_base
from sqlalchemy.orm import object_mapper, relationship, backref
from sqlalchemy.schema import Index, ForeignKeyConstraint, PrimaryKeyConstraint, CheckConstraint, Table
from sqlalchemy.types import LargeBinary

from rucio.common import utils
from rucio.db.history import Versioned

# FIXME: Breaks unit test
#@compiles(Binary, "oracle")
#def compile_binary_oracle(type_, compiler, **kw):
#    return "RAW(16)"

# FIXME: Breaks with Oracle
#@compiles(Boolean, "oracle")
#def compile_binary_oracle(type_, compiler, **kw):
#    return "CHAR(1)"


BASE = declarative_base()


class DataIdType:
    FILE = 'file'
    DATASET = 'dataset'
    CONTAINER = 'container'


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

#@event.listens_for(CheckConstraint, "after_parent_attach")
#def _ck_constraint_name(const, table):
#    column = str(const.sqltext).split()[0].replace('"','')
#    if const.name is not None:
#        const.name = "%s_%s_CHK" % (
#            table.name.upper(),
#            const.name.upper()
#        )


@event.listens_for(Table, "after_parent_attach")
def _add_created_col(table, metadata):
    table.append_column(Column("created_at", DateTime, default=datetime.datetime.utcnow()))
    table.append_column(Column("updated_at", DateTime, default=datetime.datetime.utcnow(), onupdate=datetime.datetime.utcnow()))
    table.append_column(Column("deleted_at", DateTime))
    table.append_column(Column("deleted", Boolean, default=False))


class ModelBase(object):
    """Base class for Rucio Models"""
    __table_args__ = {'mysql_engine': 'InnoDB'}

    __table_initialized__ = False
    __protected_attributes__ = set([
        "created_at", "updated_at", "deleted_at", "deleted"])

    @declared_attr
    def __table_args__(cls):
        return cls._table_args + (CheckConstraint('"CREATED_AT" IS NOT NULL', name=cls.__tablename__.upper() + '_CREATED_NN'),
                                  CheckConstraint('"UPDATED_AT" IS NOT NULL', name=cls.__tablename__.upper() + '_UPDATED_NN'),
                                  CheckConstraint('"DELETED" IS NOT NULL', name=cls.__tablename__.upper() + '_DELETED_NN'),
                                  CheckConstraint('deleted IN (0, 1)', name=cls.__tablename__.upper() + '_DELETED_CHK'),)

    def save(self, session=None):
        """Save this object"""
        session = session
        session.add(self)
        session.flush()

    def delete(self, session=None):
        """Delete this object"""
        self.deleted = True
        self.deleted_at = datetime.datetime.utcnow()
        self.save(session=session)

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


class Account(BASE, ModelBase):
    """Represents an account"""
    __tablename__ = 'accounts'
    account = Column(String(255))
    type = Column(String(10))
    status = Column(String(10))
    _table_args = (PrimaryKeyConstraint('account', name='ACCOUNTS_PK'),
                   CheckConstraint("type IN ('user', 'group', 'service')", name='ACCOUNTS_TYPE_CHK'),
                   CheckConstraint("status IN ('active', 'inactive', 'disabled')", name='ACCOUNTS_STATUS_CHK'), )


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
    account = Column(String(255))
    is_default = Column(Boolean(name='ACCOUNT_MAP_DEFAULT_CHK'), default=False)
    _table_args = (PrimaryKeyConstraint('identity', 'type', 'account', name='ACCOUNT_MAP_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='ACCOUNT_MAP_ACCOUNT_FK'),
                   ForeignKeyConstraint(['identity', 'type'], ['identities.identity', 'identities.type'], name='ACCOUNT_MAP_ID_TYPE_FK'),
                   CheckConstraint("type IN ('x509', 'gss', 'userpass')", name='ACCOUNT_MAP_TYPE_CHK'),
                   CheckConstraint('is_default IS NOT NULL', name='ACCOUNT_MAP_IS_DEFAULT_NN'),)


class Scope(BASE, ModelBase):
    """Represents a scope"""
    __tablename__ = 'scopes'
    scope = Column(String(255))
    account = Column(String(255))
    is_default = Column(Boolean(name='SCOPES_DEFAULT_CHK'), default=0)
    _table_args = (PrimaryKeyConstraint('scope', name='SCOPES_SCOPE_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='SCOPES_ACCOUNT_FK'),
                   CheckConstraint('is_default IS NOT NULL', name='SCOPES_IS_DEFAULT_NN'),)


# class DatasetKey(BASE, ModelBase):
#     """Represents dataset property keys"""
#     __tablename__ = 'dataset_keys'
#     key = Column(String(255))
#     type = Column(String(255))
#     _table_args = (PrimaryKeyConstraint('key', name='DATASET_KEYS_PK'),)
#
#
# class DatasetKeyValueAssociation(BASE, ModelBase):
#     """Represents dataset property key/values"""
#     __tablename__ = 'dataset_key_map'
#     key = Column(String(255))
#     value = Column(String(255))
#     _table_args = (PrimaryKeyConstraint('key', 'value', name='DATASET_KEY_MAP_PK'),
#                    ForeignKeyConstraint(['key'], ['dataset_keys.key'], name='DATASET_MAP_KEYS_FK'), )
#
#
# class DatasetAttribute(BASE, ModelBase):
#     """Represents dataset attributes"""
#     __tablename__ = 'dataset_attributes'
#     scope = Column(String(255))
#     name = Column(String(255))
#     key = Column(String(255))
#     value = Column(Text)
#     _table_args = (PrimaryKeyConstraint('scope', 'name', 'key', name='DATASET_ATTR_PK'),
#                    ForeignKeyConstraint(['scope', 'name'], ['datasets.scope', 'datasets.name'], name='DATASET_ATTR_FK'),
#                    ForeignKeyConstraint(['key'], ['dataset_keys.key'], name='DATASET_ATTR_KEYS_FK'),
#                    Index('DATASET_ATTR_KEY_IDX', 'key'),)


class DataIdentifier(BASE, ModelBase):
    """Represents a dataset"""
    __tablename__ = 'data_identifiers'
    scope = Column(String(255))
    did = Column(String(255))
    owner = Column(String(255))
    type = Column(String(9))
    open = Column(Boolean(name='DATASETS_OPEN_CHK'))
    monotonic = Column(Boolean(name='DATASETS_MONOTONIC_CHK'), server_default='0')
    hidden = Column(Boolean(name='DATASETS_HIDDEN_CHK'), server_default='0')
    obsolete = Column(Boolean(name='DATASETS_OBSOLETE_CHK'), server_default='0')
    complete = Column(Boolean(name='DATASETS_COMPLETE_CHK'))
    _table_args = (PrimaryKeyConstraint('scope', 'did', name='DATASETS_PK'),
                   ForeignKeyConstraint(['owner'], ['accounts.account'], ondelete='CASCADE', name='DATASETS_ACCOUNT_FK'),
                   CheckConstraint('"MONOTONIC" IS NOT NULL', name='DATASETS_MONOTONIC_NN'),
                   CheckConstraint('"OBSOLETE" IS NOT NULL', name='DATASETS_OBSOLETE_NN'),
                   CheckConstraint("type IN ('file', 'dataset', 'container')", name='DATASETS_TYPE_CHK'),)


class File(BASE, ModelBase):
    """Represents a file"""
    __tablename__ = 'files'
    scope = Column(String(255))
    did = Column(String(255))
    owner = Column(String(255))
    availability = Column(String(32))
    suppressed = Column(Boolean(name='FILES_SUPP_CHK'), server_default='0')
    size = Column(BigInteger)
    checksum = Column(String(32))
    _table_args = (PrimaryKeyConstraint('scope', 'did', name='FILES_PK'),
                   ForeignKeyConstraint(['owner'], ['accounts.account'], ondelete='CASCADE', name='FILES_ACCOUNT_FK'),
                   ForeignKeyConstraint(['scope', 'did'], ['data_identifiers.scope', 'data_identifiers.did'], name='FILES_DATA_ID_FK', ondelete="CASCADE"),
                   CheckConstraint("availability IN ('lost', 'deleted', 'available')", name='DATA_ID_TYPE_CHK'),
                   CheckConstraint('"SUPPRESSED" IS NOT NULL', name='FILES_SUPP_NN'),)


class DIDKey(BASE, ModelBase):
    """Represents Data IDentifier property keys"""
    __tablename__ = 'did_keys'
    key = Column(String(255))
    type = Column(String(255))
    regexp = Column(String(255))
    _table_args = (PrimaryKeyConstraint('key', name='DID_KEYS_PK'),)


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
    scope = Column(String(255))
    did = Column(String(255))
    key = Column(String(255))
    value = Column(String(255))
    _table_args = (PrimaryKeyConstraint('scope', 'did', 'key', name='DID_ATTR_PK'),
                   ForeignKeyConstraint(['scope', 'did'], ['data_identifiers.scope', 'data_identifiers.did'], name='DID_ATTR_SCOPE_NAME_FK'),
                   ForeignKeyConstraint(['key'], ['did_keys.key'], name='DID_ATTR_KEYS_FK'),
                   Index('DID_ATTR_KEY_IDX', 'key'),)


class DataIdentifierAssociation(BASE, ModelBase):
    """Represents the map between containers/datasets and files"""
    __tablename__ = 'contents'
    scope = Column(String(255))         # dataset scope
    did = Column(String(255))          # dataset name
    child_scope = Column(String(255))  # Provenance name scope
    child_did = Column(String(255))   # Provenance name scope
    type = Column(String(9))
    child_type = Column(String(9))
    _table_args = (PrimaryKeyConstraint('scope', 'did', 'child_scope', 'child_did', name='CONTENTS_PK'),
                   ForeignKeyConstraint(['scope', 'did'], ['data_identifiers.scope', 'data_identifiers.did'], name='CONTENTS_ID_FK'),
                   ForeignKeyConstraint(['child_scope', 'child_did'], ['data_identifiers.scope', 'data_identifiers.did'], ondelete="CASCADE", name='CONTENTS_CHILD_ID_FK'),
                   CheckConstraint("type IN ('file', 'dataset', 'container')", name='CONTENTS_TYPE_CHK'),
                   CheckConstraint("child_type IN ('file', 'dataset', 'container')", name='CONTENTS_CHILD_TYPE_CHK'),
                   Index('DATASETS_CNTS_CHILD_IDX', 'child_scope', 'child_did'),)


class RSE(BASE, ModelBase):
    """Represents a Rucio Location"""
    __tablename__ = 'rses'
    id = Column(String(36), default=utils.generate_uuid)  # in waiting to use the binary
    rse = Column(String(255))
    type = Column(String(255), default='disk')
    watermark = Column(BigInteger)
    path = Column(Text)
    usage = relationship("RSEUsage", order_by="RSEUsage.rse_id", backref="rses")
#    file_replicas = relationship("RSEFileAssociation", order_by="RSEFileAssociation.rse_id", backref="rses")
    _table_args = (PrimaryKeyConstraint('id', name='RSES_PK'),
                   UniqueConstraint('rse', name='RSES_RSE_UQ'),
                   CheckConstraint('"RSE" IS NOT NULL', name='RSES_RSE__NN'),
                   CheckConstraint("type IN ('disk')", name='RSES_TYPE_CHK'),)


class RSEUsage(BASE, ModelBase, Versioned):
    """Represents location usage"""
    __tablename__ = 'rse_usage'
    rse_id = Column(String(255))
    source = Column(String(255))
    total = Column(BigInteger)
    free = Column(BigInteger)
    rse = relationship("RSE", backref=backref('rse_usage', order_by=rse_id))
    _table_args = (PrimaryKeyConstraint('rse_id', 'source', name='RSE_USAGE_PK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='RSE_USAGE_RSE_ID_FK'), )


class RSEAttribute(BASE, ModelBase):
    """Represents RSE(Rucio Storage Element) attributes"""
    __tablename__ = 'rse_attributes'
    key = Column(String(255))
    value = Column(String(255))
    rses = relationship("RSEAttrAssociation", order_by="RSEAttrAssociation.rse_id", backref="rse_attributes")
    _table_args = (PrimaryKeyConstraint('key', 'value', name='RSE_ATTR_PK'), )


class RSEAttrAssociation(BASE, ModelBase):
    """Represents the map between RSEs and tags"""
    __tablename__ = 'rse_attr_map'
    rse_id = Column(String(36))
    key = Column(String(255))
    value = Column(String(255))
    rse = relationship("RSE", backref=backref('rse_attr_map', order_by=rse_id))
    tag = relationship("RSEAttribute", backref=backref('rse_attr_map', order_by=rse_id))
    _table_args = (PrimaryKeyConstraint('rse_id', 'key', name='RSE_ATTR_MAP_PK'),
                   ForeignKeyConstraint(['key', 'value'], ['rse_attributes.key', 'rse_attributes.value'], name='RSE_ATTR_MAP_ATTR_FK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='RSE_ATTR_MAP_RSE_ID_FK'), )


class AccountLimit(BASE, ModelBase):
    """Represents account limits"""
    __tablename__ = 'account_limits'
    account = Column(String(255))
    rse_expression = Column(String(255))
    name = Column(String(255))
    value = Column(BigInteger)
    _table_args = (PrimaryKeyConstraint('account', 'rse_expression', 'name', name='ACCOUNT_LIMITS_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='ACCOUNT_LIMITS_ACCOUNT_FK'))


class AccountUsage(BASE, ModelBase, Versioned):
    """Represents account usage"""
    __tablename__ = 'account_usage'
    account = Column(String(255))
    rse_id = Column(String(36))
    name = Column(String(255))
    value = Column(BigInteger)
    _table_args = (PrimaryKeyConstraint('account', 'rse_id', 'name', name='ACCOUNT_USAGE_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='ACCOUNT_USAGE_ACCOUNT_FK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='ACCOUNT_USAGE_RSES_ID_FK'), )


class RSEFileAssociation(BASE, ModelBase):
    """Represents the map between locations and files"""
    __tablename__ = 'file_replicas'
    rse_id = Column(String(36))
    scope = Column(String(255))
    did = Column(String(255))
    size = Column(BigInteger)
    checksum = Column(String(32))
    pfn = Column(String(1024))
    status = Column(String(255))
    rse = relationship("RSE", backref=backref('file_replicas', order_by="RSE.id"))
    _table_args = (PrimaryKeyConstraint('rse_id', 'scope', 'did', name='FILE_REPLICAS_PK'),
                   ForeignKeyConstraint(['scope', 'did'], ['files.scope', 'files.did'], name='FILE_REPLICAS_LFN_FK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='FILE_REPLICAS_RSE_ID_FK'), )
#                  CheckConstraint('"PFN" IS NOT NULL', name='FILE_REPLICAS_PFN_NN'), # for latter...


# class DatasetReplicationRule(BASE, ModelBase):
#     """Represents dataset replication rules"""
#     __tablename__ = 'dataset_rules'
#     account = Column(String(255))
#     scope = Column(String(255))
#     name = Column(String(255))
#     rse_expression = Column(String(255))
#     rses = Column(String(255))
#     replication_factor = Column(Integer(), default=1)
#     expired_at = Column(DateTime)
#     locked = Column(Boolean(name='DATASET_RULES_LOCKED_CHK'), default=False)
#     group = Column(String(512))
#     block = Column(String(512))
#     _table_args = (PrimaryKeyConstraint('account', 'scope', 'name', 'rse_expression', name='DATASET_RULES_PK'),
#                    ForeignKeyConstraint(['scope', 'name'], ['datasets.scope', 'datasets.name'], name='DATASET_RULES_DSN_FK'),
#                    ForeignKeyConstraint(['account'], ['accounts.account'], name='DATASET_RULES_ACCOUNT_FK'),
#                    CheckConstraint('"REPLICATION_FACTOR" IS NOT NULL', name='DATASET_RULES_REP_FACTOR_NN'),
#                    CheckConstraint('"LOCKED" IS NOT NULL', name='DATASET_RULES_LOCKED_NN'),)


class FileReplicationRule(BASE, ModelBase):
    """Represents file replication rules"""
    __tablename__ = 'file_rules'
    account = Column(String(255))
    scope = Column(String(255))
    did = Column(String(255))
    rse_expression = Column(String(255))
    rses = Column(String(255))
    replication_factor = Column(Integer(), default=1)
    expired_at = Column(DateTime)
    locked = Column(Boolean(name='FILE_RULES_LOCKED_CHK'), default=False)
    parent_scope = Column(String(255))  # File replication rule can be generated by a dataset
    parent_name = Column(String(255))
    _table_args = (PrimaryKeyConstraint('account', 'scope', 'did', 'rse_expression', name='FILE_RULES_PK'),
                   ForeignKeyConstraint(['scope', 'did'], ['files.scope', 'files.did'], name='FILE_RULES_SCOPE_NAME_FK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='FILE_RULES_ACCOUNT_FK'),
                   CheckConstraint('"REPLICATION_FACTOR" IS NOT NULL', name='FILE_RULES_REP_FACTOR_NN'),
                   CheckConstraint('"LOCKED" IS NOT NULL', name='FILE_RULES_LOCKED_NN'),)
#                   ForeignKeyConstraint(['account', 'rse_tag_id', 'parent_scope', 'parent_dsn'],
#                   ['dataset_rules.account', 'dataset_rules.rse_tag_id', 'dataset_rules.scope', 'dataset_rules.dsn'],
#                   name='FILE_DATASET_RULES_FK'),


class FileReplicaLock(BASE, ModelBase):
    """Represents file replica locks"""
    __tablename__ = 'file_replica_locks'
    rse_id = Column(String(36))
    scope = Column(String(255))
    did = Column(String(255))
    account = Column(String(255))
    _table_args = (PrimaryKeyConstraint('rse_id', 'scope', 'did', 'account', name='FILE_REPLICA_LOCKS_PK'),
                   ForeignKeyConstraint(['scope', 'did', 'rse_id'], ['file_replicas.scope', 'file_replicas.did', 'file_replicas.rse_id'], name='FILE_REPLICAS_FK'), )
#                   ForeignKeyConstraint(['scope', 'lfn', 'account', 'rse_tag_id'], ['file_rules.scope', 'file_rules.lfn', 'file_rules.account', 'file_rules.rse_tag_id'], name='FILE_REPLICAS_RULE_FK'),
#                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='FILE_REPLICA_LOCKS_RSE_ID_FK'),)


class Subscription(BASE, ModelBase):
    """Represents a subscription"""
    __tablename__ = 'subscriptions'
    id = Column(String(16), default=utils.generate_uuid_bytes)
    account = Column(String(255))
    retroactive = Column(Boolean(name='SUBSCRIPTIONS_RETROACTIVE_CHK'), default=False)
    expired_at = Column(DateTime)
    _table_args = (PrimaryKeyConstraint('id', 'account', name='SUBSCRIPTIONS_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='SUBSCRIPTIONS_ACCOUNT_FK'),
                   CheckConstraint('"RETROACTIVE" IS NOT NULL', name='SUBSCRIPTIONS_RETROACTIVE_NN'),)


class Authentication(BASE, ModelBase):
    """Represents the authentication tokens and their lifetime"""
    __tablename__ = 'authentication'
    token = Column(String(32))
    account = Column(String(255))
    lifetime = Column(DateTime, default=datetime.datetime.utcnow() + datetime.timedelta(seconds=3600))  # one hour lifetime by default
    ip = Column(String(16), nullable=True)
    _table_args = (PrimaryKeyConstraint('token', 'account', name='AUTH_TOKEN_ACCOUNT_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='AUTH_ACCOUNT_FK'),
                   CheckConstraint('"LIFETIME" IS NOT NULL', name='AUTH_LIFETIME_NN'),)


class APIToken(BASE, ModelBase):
    """Represents valid API clients"""
    __tablename__ = 'api_tokens'
    token = Column(String(32))
    responsible = Column(String(255))
    service_name = Column(String(255))
    call_limit = Column(Integer(), default=0)
    _table_args = (PrimaryKeyConstraint('token', name='API_TOKENS_TOKEN_PK'),
                   ForeignKeyConstraint(['responsible'], ['accounts.account'], name='API_TOKENS_ACCOUNT_FK'),)


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
              RSEAttribute,
              RSEUsage,
              AccountLimit,
              AccountUsage,
              RSEAttrAssociation,
              RSEFileAssociation,
              FileReplicationRule,
              Subscription,
              Authentication,
              APIToken)
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
              RSEAttribute,
              RSEUsage,
              AccountLimit,
              AccountUsage,
              RSEAttrAssociation,
              RSEFileAssociation,
              FileReplicationRule,
              Subscription,
              Authentication,
              APIToken)
    for model in models:
        model.metadata.drop_all(engine)
