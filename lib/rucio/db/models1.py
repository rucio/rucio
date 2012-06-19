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
import sys

from sqlalchemy import Column, Integer, String, BigInteger, Enum
from sqlalchemy import ForeignKey, DateTime, Boolean, Text
from sqlalchemy import UniqueConstraint
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref, exc, object_mapper, validates
from sqlalchemy.schema import ForeignKeyConstraint, PrimaryKeyConstraint
from sqlalchemy.types import Binary, LargeBinary

from rucio.common import utils


# FIXME: Breaks unit test
#@compiles(Binary, "oracle")
#def compile_binary_oracle(type_, compiler, **kw):
#    return "RAW(16)"


BASE = declarative_base()


class InodeType:
    FILE = 0
    DATASET = 1


class ModelBase(object):
    """Base class for Rucio Models"""
    __table_args__ = {'mysql_engine': 'InnoDB'}
    __table_initialized__ = False
    __protected_attributes__ = set([
        "created_at", "updated_at", "deleted_at", "deleted"])

    created_at = Column(DateTime, default=datetime.datetime.utcnow(),
                        nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow(),
                        nullable=False, onupdate=datetime.datetime.utcnow())
    deleted_at = Column(DateTime)
    deleted = Column(Boolean, nullable=False, default=False)

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
    account = Column(String(255), primary_key=True)
    type = Column(Enum('user', 'group', 'atlas'))
    status = Column(Enum('active', 'inactive', 'disabled'))


class Identity(BASE, ModelBase):
    """Represents an identity"""
    __tablename__ = 'identities'
    identity = Column(String(255), primary_key=True)
    type = Column(Enum('x509', 'gss', 'userpass'), primary_key=True)  # If you change this, then don't forget to change in the IdentityAccountAssociation as well
    username = Column(String(255), nullable=True)
    password = Column(String(255), nullable=True)
    salt = Column(Binary(255), nullable=True)
    email = Column(String(255), nullable=True)


class IdentityAccountAssociation(BASE, ModelBase):
    """Represents a map account-identity"""
    __tablename__ = 'account_map'
    identity = Column(String(255), primary_key=True)
    type = Column(Enum('x509', 'gss', 'userpass'), primary_key=True)
    account = Column(String(255), ForeignKey('accounts.account'), primary_key=True)
    default = Column(Boolean, nullable=False, default=False)
    __table_args__ = (ForeignKeyConstraint(['identity', 'type'], ['identities.identity', 'identities.type']), {})


class Scope(BASE, ModelBase):
    """Represents a scope"""
    __tablename__ = 'scopes'
    scope = Column(String(255), primary_key=True)
    account = Column(String(255), ForeignKey('accounts.account'))
    default = Column(Boolean, nullable=False, default=False)


class DatasetProperty(BASE, ModelBase):
    """Represents dataset properties"""
    __tablename__ = 'dataset_properties'
    scope = Column(String(255), primary_key=True)
    dsn = Column(String(255), primary_key=True)
    key = Column(String(255), index=True, primary_key=True)
    value = Column(Text)
    __table_args__ = (ForeignKeyConstraint(['scope', 'dsn'], ['datasets.scope', 'datasets.dsn']), {})


class Inode(BASE, ModelBase):
    """ A dataset or file name """
    __tablename__ = 'inodes'
    scope = Column(String(255), ForeignKey('scopes.scope'), primary_key=True)
    label = Column(String(255), primary_key=True)
    owner = Column(String(255), ForeignKey('accounts.account', deferrable=True, initially='DEFERRED', ondelete='CASCADE'))
    obsolete = Column(Boolean, nullable=False, server_default='0')
    type = Column(Boolean, nullable=False)
    monotonic = Column(Boolean)

    def __repr__(self):
        return "<Inode(%s, %s, %s, %s)" % (self.scope, self.label, self.type, self.obsolete)


class Dataset(BASE, ModelBase):
    """Represents a dataset"""
    __tablename__ = 'datasets'
    scope = Column(String(255))
    dsn = Column(String(255))
    owner = Column(String(255), ForeignKey('accounts.account', deferrable=True, initially='DEFERRED', ondelete='CASCADE', name='datasets_owner_FK'))
    open = Column(Boolean)
    monotonic = Column(Boolean, nullable=False)
    hidden = Column(Boolean)
    obsolete = Column(Boolean, nullable=False, server_default='0')
    complete = Column(Boolean)
    __table_args__ = (PrimaryKeyConstraint('scope', 'dsn', name='datasets_PK'),
                      ForeignKeyConstraint(['scope', 'dsn'], ['inodes.scope', 'inodes.label'],
                      deferrable=True, initially='DEFERRED', ondelete='CASCADE', name='datasets_scope_dsn_FK'), {})


class File(BASE, ModelBase):
    """Represents a file"""
    __tablename__ = 'files'
    scope = Column(String(255), primary_key=True)
    lfn = Column(String(255), primary_key=True)
    owner = Column(String(255), ForeignKey('accounts.account', deferrable=True, initially='DEFERRED', ondelete='CASCADE'))
    lost = Column(Boolean)
    size = Column(BigInteger)
    obsolete = Column(Boolean, nullable=True, server_default='0')
    checksum = Column(String(32))
    __table_args__ = (ForeignKeyConstraint(['scope', 'lfn'], ['inodes.scope', 'inodes.label'],
                      deferrable=True, initially='DEFERRED', ondelete="CASCADE"), {})


class FileProperty(BASE, ModelBase):
    """Represents file  properties"""
    __tablename__ = 'file_properties'
    scope = Column(String(255), primary_key=True)
    lfn = Column(String(255), primary_key=True)
    key = Column(String(255), index=True, primary_key=True)
    value = Column(Text)
    __table_args__ = (ForeignKeyConstraint(['scope', 'lfn'], ['files.scope', 'files.lfn']), {})


class DatasetFileAssociation(BASE, ModelBase):
    """Represents the map between datasets and files"""
    __tablename__ = 'dataset_contents'
    scope_dsn = Column(String(255), primary_key=True)         # Parent dataset scope
    dsn = Column(String(255), primary_key=True)               # Parent dataset name
    scope_lfn = Column(String(255), primary_key=True)         # File's scope
    lfn = Column(String(255), primary_key=True)               # File's name
    parent_inode_scope = Column(String(255), nullable=False)  # Provinance inode scope
    parent_inode_name = Column(String(255), nullable=False)   # Provinance inode scope
    obsolete = Column(Boolean, nullable=False, server_default='0')
    __table_args__ = (ForeignKeyConstraint(['scope_dsn', 'dsn'], ['datasets.scope', 'datasets.dsn'], deferrable=True, initially='DEFERRED', ondelete="NO ACTION"),
                      ForeignKeyConstraint(['scope_lfn', 'lfn'], ['files.scope', 'files.lfn'], deferrable=True, initially='DEFERRED', ondelete="CASCADE"),
                      ForeignKeyConstraint(['parent_inode_scope', 'parent_inode_name'], ['inodes.scope', 'inodes.label'], deferrable=True, initially='DEFERRED', ondelete="CASCADE"), {})


class RSE(BASE, ModelBase):
    """Represents a Rucio Storage Element (RSE)"""
    __tablename__ = 'rses'
    rse = Column(String(255), primary_key=True)
    storage = Column(String(255))
    path = Column(Text)


class RSETag(BASE, ModelBase):
    """Represents RSE tags"""
    __tablename__ = 'rse_tags'
    tag = Column(String(255), primary_key=True)
    scope = Column(String(255), nullable=True)


class RSETagAssociation(BASE, ModelBase):
    """Represents the map between RSEs and tags"""
    __tablename__ = 'rse_tag_association'
    rse = Column(String(255), ForeignKey('rses.rse'), primary_key=True)
    tag = Column(String(255), ForeignKey('rse_tags.tag'), primary_key=True)


class RSEFileAssociation(BASE, ModelBase):
    """Represents the map between RSEs and files"""
    __tablename__ = 'file_replicas'
    rse = Column(String(255), ForeignKey('rses.rse'), primary_key=True)
    scope = Column(String(255), primary_key=True)
    lfn = Column(String(255), primary_key=True)
    pfn = Column(String(1024), nullable=False)
    __table_args__ = (ForeignKeyConstraint(['scope', 'lfn'], ['files.scope', 'files.lfn'],), {})


class ReplicationRule(BASE, ModelBase):
    """Represents replication rules"""
    __tablename__ = 'replication_rules'
#    __table_args__ = (UniqueConstraint("account", "scope", "lfn", "tag"),)
    account = Column(String(255), ForeignKey('accounts.account'), primary_key=True)
    scope = Column(String(255), primary_key=True)
    lfn = Column(String(255), primary_key=True)
    tag = Column(String(255), ForeignKey('rse_tags.tag'), primary_key=True)
    replication_factor = Column(Integer(), nullable=False, default=1)
    expired_at = Column(DateTime)
    locked = Column(Boolean, nullable=False, default=False)
    __table_args__ = (ForeignKeyConstraint(['scope', 'lfn'], ['files.scope', 'files.lfn'],), {})


class Subscription(BASE, ModelBase):
    """Represents a subscription"""
    __tablename__ = 'subscriptions'
    id = Column(String(16), primary_key=True, default=utils.generate_uuid_bytes)
    account = Column(String(255), ForeignKey('accounts.account'), primary_key=True)
    retroactive = Column(Boolean, nullable=False, default=False)
    expired_at = Column(DateTime)


class Authentication(BASE, ModelBase):
    """Represents the authentication tokens and their lifetime"""
    __tablename__ = 'authentication'
    token = Column(String(32), primary_key=True)
    account = Column(String(255), ForeignKey('accounts.account'), primary_key=True)
    account = Column(String(255), primary_key=True)
    lifetime = Column(DateTime, nullable=False, default=datetime.datetime.utcnow() + datetime.timedelta(seconds=3600))  # one hour lifetime by default
    ip = Column(String(16), nullable=True)


class APIToken(BASE, ModelBase):
    """Represents valid API clients"""
    __tablename__ = 'api_tokens'
    token = Column(String(32), primary_key=True)
    responsible = Column(String(255), ForeignKey('accounts.account'))
    service_name = Column(String(255))
    call_limit = Column(Integer(), default=0)


def register_models(engine):
    """
    Creates database tables for all models with the given engine
    """
    models = (Account,
              Identity,
              IdentityAccountAssociation,
              Scope,
              DatasetProperty,
              Inode,
              Dataset,
              File,
              FileProperty,
              DatasetFileAssociation,
              RSE,
              RSETag,
              RSETagAssociation,
              RSEFileAssociation,
              ReplicationRule,
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
              Inode,
              Dataset,
              File,
              FileProperty,
              DatasetFileAssociation,
              RSE,
              RSETag,
              RSETagAssociation,
              RSEFileAssociation,
              ReplicationRule,
              Subscription,
              Authentication,
              APIToken)
    for model in models:
        model.metadata.drop_all(engine)
