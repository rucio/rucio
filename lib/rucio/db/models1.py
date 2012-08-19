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


class NameType:
    FILE = 0
    DATASET = 1


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
                   CheckConstraint("type IN ('user', 'group', 'atlas')", name='ACCOUNTS_TYPE_CHK'),
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
    default = Column(Boolean(name='ACCOUNT_MAP_DEFAULT_CHK'), default=False)
    _table_args = (PrimaryKeyConstraint('identity', 'type', 'account', name='ACCOUNT_MAP_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='ACCOUNT_MAP_ACCOUNT_FK'),
                   ForeignKeyConstraint(['identity', 'type'], ['identities.identity', 'identities.type'], name='ACCOUNT_MAP_ID_TYPE_FK'),
                   CheckConstraint("type IN ('x509', 'gss', 'userpass')", name='ACCOUNT_MAP_TYPE_CHK'),
                   CheckConstraint('"default" IS NOT NULL', name='ACCOUNT_MAP_DEFAULT_NN'),)


class Scope(BASE, ModelBase):
    """Represents a scope"""
    __tablename__ = 'scopes'
    scope = Column(String(255))
    account = Column(String(255))
    default = Column(Boolean(name='SCOPES_DEFAULT_CHK'), default=0)
    _table_args = (PrimaryKeyConstraint('scope', name='SCOPES_SCOPE_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='SCOPES_ACCOUNT_FK'),
                   CheckConstraint('"default" IS NOT NULL', name='SCOPES_DEFAULT_NN'),)


class DatasetKey(BASE, ModelBase):
    """Represents dataset property keys"""
    __tablename__ = 'dataset_keys'
    key = Column(String(255))
    type = Column(String(255))
    _table_args = (PrimaryKeyConstraint('key', name='DATASET_KEYS_PK'),)


class DatasetKeyValueAssociation(BASE, ModelBase):
    """Represents dataset property key/values"""
    __tablename__ = 'dataset_key_map'
    key = Column(String(255))
    value = Column(String(255))
    _table_args = (PrimaryKeyConstraint('key', 'value', name='DATASET_KEY_MAP_PK'),
                   ForeignKeyConstraint(['key'], ['dataset_keys.key'], name='DATASET_MAP_KEYS_FK'), )


class DatasetProperty(BASE, ModelBase):
    """Represents dataset properties"""
    __tablename__ = 'dataset_properties'
    scope = Column(String(255))
    dsn = Column(String(255))
    key = Column(String(255))
    value = Column(Text)
    _table_args = (PrimaryKeyConstraint('scope', 'dsn', 'key', name='DATASET_PROPERTIES_PK'),
                   ForeignKeyConstraint(['scope', 'dsn'], ['datasets.scope', 'datasets.dsn'], name='DATASET_PROPERTIES_FK'),
                   ForeignKeyConstraint(['key'], ['dataset_keys.key'], name='DATASET_PROPERTIES_KEYS_FK'),
                   Index('DATASET_PROPERTIES_KEY_IDX', 'key'),)


class Name(BASE, ModelBase):
    """ A dataset or file name """
    __tablename__ = 'names'
    scope = Column(String(255))
    name = Column(String(255))
    owner = Column(String(255))
    obsolete = Column(Boolean(name='NAMES_OBSOLETE_CHK'), server_default='0')
    type = Column(Boolean(name='NAMES_TYPE_CHK'))
    monotonic = Column(Boolean(name='NAMES_MONOTONIC_CHK'), default=False)
    _table_args = (PrimaryKeyConstraint('scope', 'name', name='NAMES_PK'),
                   ForeignKeyConstraint(['scope'], ['scopes.scope'], name='NAMES_SCOPE_FK'),
                   ForeignKeyConstraint(['owner'], ['accounts.account'], name='NAMES_ACCOUNT_FK'),
                   CheckConstraint('"OBSOLETE" IS NOT NULL', name='NAMES_OBSOLETE_NN'),
                   CheckConstraint('"TYPE" IS NOT NULL', name='NAMES_TYPE_NN'),
                   CheckConstraint('"MONOTONIC" IS NOT NULL', name='NAMES_MONOTONIC_NN'),)

    def __repr__(self):
        return "<NAme(%s, %s, %s, %s)" % (self.scope, self.name, self.type, self.obsolete)


class Dataset(BASE, ModelBase):
    """Represents a dataset"""
    __tablename__ = 'datasets'
    scope = Column(String(255))
    dsn = Column(String(255))
    owner = Column(String(255))
    open = Column(Boolean(name='DATASETS_OPEN_CHK'))
    monotonic = Column(Boolean(name='DATASETS_MONOTONIC_CHK'), server_default='0')
    hidden = Column(Boolean(name='DATASETS_HIDDEN_CHK'), server_default='0')
    obsolete = Column(Boolean(name='DATASETS_OBSOLETE_CHK'), server_default='0')
    complete = Column(Boolean(name='DATASETS_COMPLETE_CHK'))
    _table_args = (PrimaryKeyConstraint('scope', 'dsn', name='DATASETS_PK'),
                   ForeignKeyConstraint(['scope', 'dsn'], ['names.scope', 'names.name'], ondelete='CASCADE', name='DATASETS_SCOPE_DSN_FK'),
                   ForeignKeyConstraint(['owner'], ['accounts.account'], ondelete='CASCADE', name='DATASETS_ACCOUNT_FK'),
                   CheckConstraint('"MONOTONIC" IS NOT NULL', name='DATASETS_MONOTONIC_NN'),
                   CheckConstraint('"OBSOLETE" IS NOT NULL', name='DATASETS_OBSOLETE_NN'),)


class File(BASE, ModelBase):
    """Represents a file"""
    __tablename__ = 'files'
    scope = Column(String(255))
    lfn = Column(String(255))
    owner = Column(String(255))
    lost = Column(Boolean(name='FILES_LOST_CHK'))
    size = Column(BigInteger)
    obsolete = Column(Boolean(name='FILES_OBSOLETE_CHK'), server_default='0')
    checksum = Column(String(32))
    _table_args = (PrimaryKeyConstraint('scope', 'lfn', name='FILES_PK'),
                   ForeignKeyConstraint(['owner'], ['accounts.account'], ondelete='CASCADE', name='FILES_ACCOUNT_FK'),
                   ForeignKeyConstraint(['scope', 'lfn'], ['names.scope', 'names.name'], ondelete="CASCADE"),
                   CheckConstraint('"OBSOLETE" IS NOT NULL', name='FILES_OBSOLETE_NN'),)


class FileKey(BASE, ModelBase):
    """Represents file property keys"""
    __tablename__ = 'file_keys'
    key = Column(String(255))
    type = Column(String(255))
    _table_args = (PrimaryKeyConstraint('key', name='FILE_KEYS_PK'),)


class FileKeyValueAssociation(BASE, ModelBase):
    """Represents file property key/values"""
    __tablename__ = 'file_key_map'
    key = Column(String(255))
    value = Column(String(255))
    _table_args = (PrimaryKeyConstraint('key', 'value', name='FILE_KEY_MAP_PK'),
                   ForeignKeyConstraint(['key'], ['file_keys.key'], name='FILE_MAP_KEYS_FK'),)


class FileProperty(BASE, ModelBase):
    """Represents file  properties"""
    __tablename__ = 'file_properties'
    scope = Column(String(255))
    lfn = Column(String(255))
    key = Column(String(255))
    value = Column(String(255))
    _table_args = (PrimaryKeyConstraint('scope', 'lfn', 'key', name='FILES_PROPERTIES_PK'),
                   ForeignKeyConstraint(['scope', 'lfn'], ['files.scope', 'files.lfn'], name='FILES_PROPERTIES_SCOPE_LFN_FK'),
                   ForeignKeyConstraint(['key'], ['file_keys.key'], name='FILE_PROPERTIES_KEYS_FK'),
                   Index('FILE_PROPERTIES_KEY_IDX', 'key'),)


class DatasetFileAssociation(BASE, ModelBase):
    """Represents the map between datasets and files"""
    __tablename__ = 'dataset_contents'
    scope_dsn = Column(String(255))         # Parent dataset scope
    dsn = Column(String(255))               # Parent dataset name
    scope_lfn = Column(String(255))         # File's scope
    lfn = Column(String(255))               # File's name
    parent_scope = Column(String(255))  # Provenance name scope
    parent_name = Column(String(255))   # Provenance name scope
    obsolete = Column(Boolean(name='DATASET_CONTENTS_OBSOLETE_CHK'), server_default='0')
    _table_args = (PrimaryKeyConstraint('scope_dsn', 'dsn', 'scope_lfn', 'lfn', name='DATASET_CONTENTS_PK'),
                   ForeignKeyConstraint(['scope_dsn', 'dsn'], ['datasets.scope', 'datasets.dsn'], name='DATASET_CONTENTS_DSN_FK'),  # ondelete="NO ACTION" problem with Oracle
                   ForeignKeyConstraint(['scope_lfn', 'lfn'], ['files.scope', 'files.lfn'], ondelete="CASCADE", name='DATASET_CONTENTS_LFN_FK'),
                   ForeignKeyConstraint(['parent_scope', 'parent_name'], ['names.scope', 'names.name'], ondelete="CASCADE", name='DATASET_CONTENTS_NAMES_FK'),
                   CheckConstraint('"PARENT_SCOPE" IS NOT NULL', name='DATASET_CONTENTS_P_SCOPE_NN'),
                   CheckConstraint('"PARENT_NAME" IS NOT NULL', name='DATASET_CONTENTS_P_NAME_NN'),
                   CheckConstraint('"OBSOLETE" IS NOT NULL', name='DATASET_CONTENTS_OBSOLETE_NN'),
                   )


class RSE(BASE, ModelBase):
    """Represents a Rucio Location"""
    __tablename__ = 'rses'
    id = Column(String(36), default=utils.generate_uuid)  # in waiting to use the binary
    rse = Column(String(255))
    type = Column(String(255), default='disk')
    watermark = Column(BigInteger)
    path = Column(Text)
    usage = relationship("RSEUsage", order_by="RSEUsage.rse_id", backref="rses")
    #rse = relationship("LocationRSEAssociation", order_by="LocationRSEAssociation.location_id", backref="locations")
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


class RSETag(BASE, ModelBase):
    """Represents RSE (Rucio Storage Element)"""
    __tablename__ = 'rse_tags'
    id = Column(String(36), default=utils.generate_uuid)  # in waiting to use the binary
    tag = Column(String(255))
    description = Column(String(255), nullable=True)
    rses = relationship("RSETagAssociation", order_by="RSETagAssociation.rse_id", backref="rse_tags")
    _table_args = (PrimaryKeyConstraint('id', name='RSE_TAGS_PK'),
                   UniqueConstraint('tag', name='RSE_TAGS_TAG_UQ'),
                   CheckConstraint('"TAG" IS NOT NULL', name='RSES_TAGS_TAG_NN'),)


class RSETagAssociation(BASE, ModelBase):
    """Represents the map between RSEs and tags"""
    __tablename__ = 'rse_tag_map'
    rse_id = Column(String(36))
    rse_tag_id = Column(String(36))
    rse = relationship("RSE", backref=backref('rse_tag_map', order_by=rse_id))
    tag = relationship("RSETag", backref=backref('rse_tag_map', order_by=rse_id))
    _table_args = (PrimaryKeyConstraint('rse_id', 'rse_tag_id', name='RSE_TAG_MAP_PK'),
                   ForeignKeyConstraint(['rse_tag_id'], ['rse_tags.id'], name='RSE_TAG_MAP_TAG_ID_FK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='RSE_TAG_MAP_RSE_ID_FK'), )


class AccountLimit(BASE, ModelBase):
    """Represents account limits"""
    __tablename__ = 'account_limits'
    account = Column(String(255))
    rse_tag_id = Column(String(36))
    name = Column(String(255))
    value = Column(BigInteger)
    _table_args = (PrimaryKeyConstraint('account', 'rse_tag_id', 'name', name='ACCOUNT_LIMITS_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='ACCOUNT_LIMITS_ACCOUNT_FK'),
                   ForeignKeyConstraint(['rse_tag_id'], ['rse_tags.id'], name='ACCOUNT_LIMITS_RSE_TAG_ID_FK'), )


class AccountUsage(BASE, ModelBase, Versioned):
    """Represents account usage"""
    __tablename__ = 'account_usage'
    account = Column(String(255))
    rse_tag_id = Column(String(36))
    name = Column(String(255))
    value = Column(BigInteger)
    _table_args = (PrimaryKeyConstraint('account', 'rse_tag_id', 'name', name='ACCOUNT_USAGE_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='ACCOUNT_USAGE_ACCOUNT_FK'),
                   ForeignKeyConstraint(['rse_tag_id'], ['rse_tags.id'], name='ACCOUNT_USAGE_RSE_TAG_ID_FK'), )


class RSEFileAssociation(BASE, ModelBase):
    """Represents the map between locations and files"""
    __tablename__ = 'file_replicas'
    rse_id = Column(String(36))
    scope = Column(String(255))
    lfn = Column(String(255))
    pfn = Column(String(1024))
    status = Column(String(255))
    _table_args = (PrimaryKeyConstraint('rse_id', 'scope', 'lfn', name='FILE_REPLICAS_PK'),
                   ForeignKeyConstraint(['scope', 'lfn'], ['files.scope', 'files.lfn'], name='FILE_REPLICAS_SCOPE_LFN_FK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='FILE_REPLICAS_RSE_ID_FK'), )
#                  CheckConstraint('"PFN" IS NOT NULL', name='FILE_REPLICAS_PFN_NN'), # for latter...


class DatasetReplicationRule(BASE, ModelBase):
    """Represents dataset replication rules"""
    __tablename__ = 'dataset_rules'
    account = Column(String(255))
    scope = Column(String(255))
    dsn = Column(String(255))
    rse_tag_id = Column(String(36))
    replication_factor = Column(Integer(), default=1)
    expired_at = Column(DateTime)
    locked = Column(Boolean(name='DATASET_RULES_LOCKED_CHK'), default=False)
    group = Column(String(512))
    block = Column(String(512))
    _table_args = (PrimaryKeyConstraint('account', 'scope', 'dsn', 'rse_tag_id', name='DATASET_RULES_PK'),
                   ForeignKeyConstraint(['scope', 'dsn'], ['datasets.scope', 'datasets.dsn'], name='DATASET_RULES_SCOPE_LFN_FK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='DATASET_RULES_ACCOUNT_FK'),
                   ForeignKeyConstraint(['rse_tag_id'], ['rse_tags.id'], name='DATASET_RULES_RSE_TAG_ID_FK'),
                   CheckConstraint('"REPLICATION_FACTOR" IS NOT NULL', name='DATASET_RULES_REP_FACTOR_NN'),
                   CheckConstraint('"LOCKED" IS NOT NULL', name='DATASET_RULES_LOCKED_NN'),)


class FileReplicationRule(BASE, ModelBase):
    """Represents file replication rules"""
    __tablename__ = 'file_rules'
    account = Column(String(255))
    scope = Column(String(255))
    lfn = Column(String(255))
    rse_tag_id = Column(String(36))
    replication_factor = Column(Integer(), default=1)
    expired_at = Column(DateTime)
    locked = Column(Boolean(name='FILE_RULES_LOCKED_CHK'), default=False)
    parent_scope = Column(String(255))  # File replication rule can be generated by a dataset
    parent_dsn = Column(String(255))
    group = Column(String(512))
    block = Column(String(512))
    _table_args = (PrimaryKeyConstraint('account', 'scope', 'lfn', 'rse_tag_id', name='FILE_RULES_PK'),
                   ForeignKeyConstraint(['scope', 'lfn'], ['files.scope', 'files.lfn'], name='FILE_RULES_SCOPE_LFN_FK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='FILE_RULES_ACCOUNT_FK'),
                   ForeignKeyConstraint(['rse_tag_id'], ['rse_tags.id'], name='FILE_RULES_RSE_TAG_ID_FK'),
                   ForeignKeyConstraint(['account', 'rse_tag_id', 'parent_scope', 'parent_dsn'],
                   ['dataset_rules.account', 'dataset_rules.rse_tag_id', 'dataset_rules.scope', 'dataset_rules.dsn'],
                   name='FILE_DATASET_RULES_FK'),
                   CheckConstraint('"REPLICATION_FACTOR" IS NOT NULL', name='FILE_RULES_REP_FACTOR_NN'),
                   CheckConstraint('"LOCKED" IS NOT NULL', name='FILE_RULES_LOCKED_NN'),)


class FileReplicaLock(BASE, ModelBase):
    """Represents file replica locks"""
    __tablename__ = 'file_replica_locks'
    rse_id = Column(String(36))
    scope = Column(String(255))
    lfn = Column(String(255))
    account = Column(String(255))
    rse_tag_id = Column(String(36))
    _table_args = (PrimaryKeyConstraint('rse_id', 'scope', 'lfn', 'account', name='FILE_REPLICA_LOCKS_PK'),
                   ForeignKeyConstraint(['scope', 'lfn', 'account', 'rse_tag_id'], ['file_rules.scope', 'file_rules.lfn', 'file_rules.account', 'file_rules.rse_tag_id'], name='FILE_REPLICAS_RULE_FK'),
                   ForeignKeyConstraint(['scope', 'lfn', 'rse_id'], ['file_replicas.scope', 'file_replicas.lfn', 'file_replicas.rse_id'], name='FILE_REPLICAS_FK'), )
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
              DatasetProperty,
              Name,
              Dataset,
              File,
              FileProperty,
              DatasetFileAssociation,
              RSE,
              RSETag,
              RSEUsage,
              AccountLimit,
              AccountUsage,
              RSETagAssociation,
              RSEFileAssociation,
              FileReplicationRule,
              DatasetReplicationRule,
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
              DatasetProperty,
              Name,
              Dataset,
              File,
              FileProperty,
              DatasetFileAssociation,
              RSE,
              RSETag,
              RSEUsage,
              AccountLimit,
              AccountUsage,
              RSETagAssociation,
              RSEFileAssociation,
              FileReplicationRule,
              DatasetReplicationRule,
              Subscription,
              Authentication,
              APIToken)
    for model in models:
        model.metadata.drop_all(engine)
