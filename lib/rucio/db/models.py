# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne,  <vincent.garonne@cern.ch> , 2011
"""
SQLAlchemy models for rucio data
"""

import datetime
import sys

from sqlalchemy.orm    import relationship, backref, exc, object_mapper, validates
from sqlalchemy        import Column, Integer, String, BigInteger, Enum
from sqlalchemy        import ForeignKey, DateTime, Boolean, Text
from sqlalchemy        import UniqueConstraint
from sqlalchemy.schema import ForeignKeyConstraint
from sqlalchemy.ext.declarative import declarative_base


BASE = declarative_base()


class ModelBase(object):
    """Base class for Rucio Models"""
    __table_args__ = {'mysql_engine': 'InnoDB'}
    __table_initialized__ = False
    __protected_attributes__ = set([
        "created_at", "updated_at", "deleted_at", "deleted"])

    created_at = Column(DateTime, default=datetime.datetime.utcnow,
                        nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow,
                        nullable=False, onupdate=datetime.datetime.utcnow)
    deleted_at = Column(DateTime)
    deleted    = Column(Boolean, nullable=False, default=False)

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

class Identity(BASE, ModelBase):
    """Represents an identity in the datastore"""
    __tablename__ = 'identities'
    id   = Column(String(255), primary_key=True)
    type = Column(Enum('x509','gss'))

class Account(BASE, ModelBase):
    """Represents an account in the datastore"""
    __tablename__ = 'accounts'
    account = Column(String(255), primary_key=True)
    type    = Column(Enum('user','group','atlas'))

class IdentityAccountAssociation(BASE, ModelBase):
    """Represents a map account-identity in the datastore"""
    __tablename__ = 'account_map'
    identity_id = Column(String(255), ForeignKey('identities.id'),    primary_key=True)
    account     = Column(String(255), ForeignKey('accounts.account'), primary_key=True)
    default     = Column(Boolean, nullable=False, default=False)

class Scope(BASE, ModelBase):
    """Represents a scope in the datastore"""
    __tablename__ = 'scopes'
    scope   = Column(String(255), primary_key=True)
    account = Column(String(255), ForeignKey('accounts.account'))
    default = Column(Boolean, nullable=False, default=False)


class DatasetProperty(BASE, ModelBase):
    """Represents a dataset properties"""
    __tablename__ = 'dataset_properties'
    scope         = Column(String(255), primary_key=True)
    dsn           = Column(String(255), primary_key=True)
    key           = Column(String(255), index=True, primary_key=True)
    value         = Column(Text)
    dataset       = relationship('Dataset', foreign_keys=(scope, dsn))
    ForeignKeyConstraint(['scope', 'dsn'], ['datasets.scope',  'datasets.dsn'])


#class Node(BASE, ModelBase):
#    """Represents a node in the datastore"""
#    __tablename__ = 'nodes'
#    scope         = Column(String(255), ForeignKey('scopes.scope'),  primary_key=True)
#    name          = Column(String(255), primary_key=True)
#    type          = Column(Enum('file', 'dataset'))
#    open          = Column(Boolean)
#    monotonic     = Column(Boolean)
#    hidden        = Column(Boolean)
#    obsolete      = Column(Boolean)
#    complete      = Column(Boolean)
#    obsolete      = Column(Boolean)
#    lost          = Column(Boolean)
#    size          = Column(BigInteger)
#    checksum      = Column(String(32))
#
#class Aggregations(BASE, ModelBase):
#    """Represents a node in the datastore"""
#    __tablename__ = 'aggregations'
#    scope_dsn     = Column(String(255), ForeignKey('nodes.scope'),  primary_key=True)
#    dsn           = Column(String(255), ForeignKey('nodes.name'),  primary_key=True)
#    scope_lfn     = Column(String(255), ForeignKey('nodes.scope'),  primary_key=True)
#    lfn           = Column(String(255), ForeignKey('nodes.name'),  primary_key=True)


class Dataset(BASE, ModelBase):
    """Represents a scope in the datastore"""
    __tablename__ = 'datasets'
    scope      = Column(String(255), ForeignKey('scopes.scope'),  primary_key=True)
    dsn        = Column(String(255), primary_key=True)
    open       = Column(Boolean)
    monotonic  = Column(Boolean)
    hidden     = Column(Boolean)
    obsolete   = Column(Boolean)
    complete   = Column(Boolean)
    properties = relationship(DatasetProperty, cascade="all")


class File(BASE, ModelBase):
    """Represents a scope in the datastore"""
    __tablename__ = 'files'
    scope    = Column(String(255), ForeignKey('scopes.scope'),  primary_key=True)
    lfn      = Column(String(255), primary_key=True)
    obsolete = Column(Boolean)
    lost     = Column(Boolean)
    size     = Column(BigInteger)
    checksum = Column(String(32))


class FileProperty(BASE, ModelBase):
    """Represents a dataset properties"""
    __tablename__ = 'file_properties'
    scope      = Column(String(255), primary_key=True)
    lfn        = Column(String(255), primary_key=True)
    key        = Column(String(255), index=True, primary_key=True)
    value      = Column(Text)
    ForeignKeyConstraint(['scope', 'lfn'], ['files.scope', 'files.lfn'],
    use_alter=True, name='fk_file_properties')

class DatasetFileAssociation(BASE, ModelBase):
    __tablename__ = 'dataset_contents'
    scope_dsn     = Column(String(255), primary_key=True)
    dsn           = Column(String(255), primary_key=True)
    scope_lfn     = Column(String(255), primary_key=True)
    lfn           = Column(String(255), primary_key=True)
    parent_scope  = Column(String(255), nullable=True)
    parent_dsn    = Column(String(255), nullable=True)
    ForeignKeyConstraint(['scope_dsn', 'dsn'], ['datasets.scope',  'datasets.dsn'])
    ForeignKeyConstraint(['scope_lfn', 'lfn'], ['files.scope',     'files.lfn'])


class RSE(BASE, ModelBase):
    """Represents a scope in the datastore"""
    __tablename__ = 'rses'
    rse      = Column(String(255), primary_key=True)
    storage  = Column(String(255))
    path     = Column(Text)

class RSETag(BASE, ModelBase):
    """Represents a RSE tag"""
    __tablename__ = 'rse_tags'
    tag    = Column(String(255), primary_key=True)
    scope  = Column(String(255), nullable=True)

class RSETagAssociation(BASE, ModelBase):
    """Represents a scope in the datastore"""
    __tablename__ = 'rse_tag_association'
    rse      = Column(String(255), ForeignKey('rses.rse'), primary_key=True)
    tag      = Column(String(255), ForeignKey('rse_tags.tag'), primary_key=True)

class RSEFileAssociation(BASE, ModelBase):
    """Represents a scope in the datastore"""
    __tablename__ = 'file_replicas'
    rse      = Column(String(255),  ForeignKey('rses.rse'), primary_key=True)
    scope    = Column(String(255), primary_key=True)
    lfn      = Column(String(255),   primary_key=True)
    ForeignKeyConstraint(['scope', 'lfn'], ['files.scope', 'files.lfn'])

class ReplicationRule(BASE, ModelBase):
    """Represents a scope in the datastore"""
    __tablename__ = 'replication_rules'
#    __table_args__ = (UniqueConstraint("account", "scope", "lfn", "tag"),)
    account            = Column(String(255), ForeignKey('accounts.account'),primary_key=True)
    scope              = Column(String(255),primary_key=True)
    lfn                = Column(String(255),primary_key=True)
    tag                = Column(String(255), ForeignKey('rse_tags.tag'),primary_key=True)
    replication_factor = Column(Integer(), nullable=False, default=1)
    expired_at         = Column(DateTime)
    locked             = Column(Boolean, nullable=False, default=False)
    ForeignKeyConstraint(['scope', 'lfn'], ['files.scope', 'files.lfn'])


def register_models(engine):
    """
    Creates database tables for all models with the given engine
    """
    models = (Account, Scope, Dataset, DatasetProperty, File, FileProperty)
    for model in models:
        model.metadata.create_all(engine)

def unregister_models(engine):
    """
    Drops database tables for all models with the given engine
    """
    models = (Account, Scope, Dataset, DatasetProperty, File, FileProperty)
    for model in models:
        model.metadata.drop_all(engine)
