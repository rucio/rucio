# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Angelos Molfetas <angelos.molfetas@cern.ch>, 2011

"""
SQLAlchemy models for rucio schema
"""

from sqlalchemy import create_engine, Table, Column, Integer, String, Boolean, DateTime, Enum, ForeignKey
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

#engine = create_engine('sqlite:///:memory:', echo=True)
engine = create_engine('sqlite:////tmp/rucio.db', echo=True)

""" Assigned credentials to accounts """
AssignedCredentials = Table('association', Base.metadata,
    Column('name', String, ForeignKey('accounts.name'), primary_key=True),
    Column('id', Integer, ForeignKey('credentials.id'), primary_key=True))


class Account(Base):
    """ User Accounts """
    __tablename__ = 'accounts'
    name = Column(String, primary_key=True)
    type = Column(Enum('individual', 'activity'), nullable=False)
    state = Column(Enum('active', 'expired', 'disabled'), nullable=False)
    cdate = Column(DateTime, nullable=False)
    credentials = relationship("Credential", secondary=AssignedCredentials, backref="accounts")
    scopes = relationship("Scope", backref="accounts")

    def __init__(self, account_name, account_type=1, account_state=1):
        self.name = account_name
        self.type = account_type
        self.state = account_state
        self.cdate = datetime.datetime()

    def __repr__(self):
        return "<Account('%s', '%s', '%s')>" % (self.name, self.type, self.state)


class Credential(Base):
    """ Credentials for authentication """
    __tablename__ = 'credentials'
    id = Column(Integer, primary_key=True, autoincrement=True)
    type = Column(Enum('password', 'proxy'), nullable=False)
    credential = Column(String, nullable=False)
    dateadded = Column(DateTime, nullable=False)
    expiration = Column(Integer, nullable=False)

    def __init__(self, credentialtype, credential, expiration):
        self.type = credentialtype
        self.credential = Column(String, nullable=False)
        self.dateadded = datetime.datetime()
        self.expiration = expiration

    def __repr__(self):
        return "<Credential('%s', '%s', '%s')>" % (self.id, self.type)


class Scope(Base):
    """ Account linked namespaces for Datasets and Files """
    __tablename__ = 'scopes'
    scope = Column(String, primary_key=True)
    description = Column(String, nullable=True)
    accname = Column(String, ForeignKey('accounts.name'), nullable=False)

Base.metadata.create_all(engine)
