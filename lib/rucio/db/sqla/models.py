# Copyright 2015-2020 CERN for the benefit of the ATLAS collaboration.
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
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2017
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012-2020
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2012
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2013
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2020
# - Martin Barisits, <martin.barisits@cern.ch>, 2013-2020
# - Wen Guan, <wen.guan@cern.ch>, 2015
# - Joaquin Bogado <jbogado@linti.unlp.edu.ar>, 2015-2019
# - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2019
# - Andrew Lister, <andrew.lister@stfc.ac.uk>, 2019
# - Ruturaj Gujar, <ruturaj.gujar23@gmail.com>, 2019
# - Jaroslav Guenther, <jaroslav.guenther@cern.ch>, 2019
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
#
# PY3K COMPATIBLE

import datetime
import sys
import uuid

from six import iteritems
from sqlalchemy import BigInteger, Boolean, Column, DateTime, Float, Integer, SmallInteger, String as _String, Text, event, UniqueConstraint
from sqlalchemy.engine import Engine
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import object_mapper, relationship, backref
from sqlalchemy.schema import Index, ForeignKeyConstraint, PrimaryKeyConstraint, CheckConstraint, Table
from sqlalchemy.sql import Delete
from sqlalchemy.types import LargeBinary

from rucio.common import utils
from rucio.common.schema import get_schema_value
from rucio.db.sqla.constants import (AccountStatus, AccountType, DIDAvailability, DIDType, DIDReEvaluation,
                                     KeyType, IdentityType, LockState, RuleGrouping, BadFilesStatus,
                                     RuleState, ReplicaState, RequestState, RequestType, RSEType,
                                     ScopeStatus, SubscriptionState, RuleNotification, LifetimeExceptionsState,
                                     BadPFNStatus)
from rucio.db.sqla.history import Versioned
from rucio.db.sqla.session import BASE
from rucio.db.sqla.types import GUID, BooleanString, JSON
from rucio.db.sqla.types import InternalAccountString as _InternalAccountString
from rucio.db.sqla.types import InternalScopeString as _InternalScopeString


# Recipe to force str instead if unicode
# https://groups.google.com/forum/#!msg/sqlalchemy/8Xn31vBfGKU/bAGLNKapvSMJ
def String(*arg, **kw):
    if sys.version_info[0] < 3:
        kw['convert_unicode'] = 'force'
    return _String(*arg, **kw)


def InternalScopeString(*arg, **kw):
    if sys.version_info[0] < 3:
        kw['convert_unicode'] = 'force'
    return _InternalScopeString(*arg, **kw)


def InternalAccountString(*arg, **kw):
    if sys.version_info[0] < 3:
        kw['convert_unicode'] = 'force'
    return _InternalAccountString(*arg, **kw)


@compiles(Boolean, "oracle")
def compile_binary_oracle(type_, compiler, **kw):
    return "NUMBER(1)"


# PostgreSQL expects foreign keys to have the same type.
# Unfortunately, SQLAlchemy propagates the name into the type for the PostgreSQL driver,
# For now, we need to force rename that one case where this happens.
@event.listens_for(Table, "before_create")
def _psql_rename_type(target, connection, **kw):
    if connection.dialect.name == 'postgresql' and target.name == 'account_map':
        target.columns.identity_type.type.impl.name = 'IDENTITIES_TYPE_CHK'
    elif connection.dialect.name == 'mysql' and target.name == 'quarantined_replicas_history':
        target.columns.path.type = String(255)
    elif connection.dialect.name == 'mysql' and target.name == 'quarantined_replicas':
        target.columns.path.type = String(255)


@event.listens_for(Table, "before_create")
def _oracle_json_constraint(target, connection, **kw):
    if connection.dialect.name == 'oracle' and target.name == 'did_meta':
        try:
            oracle_version = int(connection.connection.version.split('.')[0])
        except Exception:
            return
        if oracle_version >= 12:
            target.append_constraint(CheckConstraint('META IS JSON', 'ORACLE_META_JSON_CHK'))


@event.listens_for(Engine, "before_execute", retval=True)
def _add_hint(conn, element, multiparams, params):
    if conn.dialect.name == 'oracle' and isinstance(element, Delete) and element.table.name == 'locks':
        element = element.prefix_with("/*+ INDEX(LOCKS LOCKS_PK) */")
    if conn.dialect.name == 'oracle' and isinstance(element, Delete) and element.table.name == 'replicas':
        element = element.prefix_with("/*+ INDEX(REPLICAS REPLICAS_PK) */")
    if conn.dialect.name == 'oracle' and isinstance(element, Delete) and element.table.name == 'dids':
        element = element.prefix_with("/*+ INDEX(DIDS DIDS_PK) */")
    if conn.dialect.name == 'oracle' and isinstance(element, Delete) and element.table.name == 'updated_dids':
        element = element.prefix_with("/*+ INDEX(updated_dids UPDATED_DIDS_SCOPERULENAME_IDX) */")
    if conn.dialect.name == 'oracle' and isinstance(element, Delete) and element.table.name == 'tokens':
        element = element.prefix_with("/*+ INDEX(TOKENS_ACCOUNT_EXPIRED_AT_IDX) */")
    return element, multiparams, params


@event.listens_for(PrimaryKeyConstraint, "after_parent_attach")
def _pk_constraint_name(const, table):
    if table.name.upper() == 'QUARANTINED_REPLICAS_HISTORY':
        const.name = "QRD_REPLICAS_HISTORY_PK"
    else:
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
    if const.name:
        return
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
    elif const.name == 'QUARANTINED_REPLICAS_CREATED_NN' and table.name.upper() == 'QUARANTINED_REPLICAS':
        const.name = "QURD_REPLICAS_CREATED_NN"
    elif const.name == 'QUARANTINED_REPLICAS_UPDATED_NN' and table.name.upper() == 'QUARANTINED_REPLICAS':
        const.name = "QURD_REPLICAS_UPDATED_NN"
    elif const.name == 'ARCHIVE_CONTENTS_HISTORY_CREATED_NN' and table.name.upper() == 'ARCHIVE_CONTENTS_HISTORY':
        const.name = "ARCH_CNTS_HIST_CREATED_NN"
    elif const.name == 'ARCHIVE_CONTENTS_HISTORY_UPDATED_NN' and table.name.upper() == 'ARCHIVE_CONTENTS_HISTORY':
        const.name = "ARCH_CNTS_HIST_UPDATED_NN"

    if const.name is None:
        const.name = table.name.upper() + '_' + str(uuid.uuid4())[:6] + '_CHK'


@event.listens_for(Table, "after_parent_attach")
def _add_created_col(table, metadata):
    if not table.name.upper():
        pass

    if not table.name.upper().endswith('_HISTORY'):
        if table.info.get('soft_delete', False):
            table.append_column(Column("deleted", Boolean, default=False))
            table.append_column(Column("deleted_at", DateTime))


class ModelBase(object):
    """Base class for Rucio Models"""
    __table_initialized__ = False

    @declared_attr
    def __table_args__(cls):  # pylint: disable=no-self-argument
        # exception for CERN Oracle identifier length limitations
        # pylint: disable=maybe-no-member
        if cls.__tablename__.upper() == 'UPDATED_ACCOUNT_COUNTERS':
            return cls._table_args + (CheckConstraint('CREATED_AT IS NOT NULL', 'UPDATED_ACCNT_CNTRS_CREATED_NN'),
                                      CheckConstraint('UPDATED_AT IS NOT NULL', 'UPDATED_ACCNT_CNTRS_UPDATED_NN'),
                                      {'mysql_engine': 'InnoDB'})
        # pylint: disable=maybe-no-member
        elif cls.__tablename__.upper() == 'UPDATED_RSE_COUNTERS':
            return cls._table_args + (CheckConstraint('CREATED_AT IS NOT NULL', 'UPDATED_RSE_CNTRS_CREATED_NN'),
                                      CheckConstraint('UPDATED_AT IS NOT NULL', 'UPDATED_RSE_CNTRS_UPDATED_NN'),
                                      {'mysql_engine': 'InnoDB'})
        # pylint: disable=maybe-no-member
        elif cls.__tablename__.upper() == 'DIDS_FOLLOWED_EVENTS':
            return cls._table_args + (CheckConstraint('CREATED_AT IS NOT NULL', 'DIDS_FOLLOWED_EVENTS_CRE_NN'),
                                      CheckConstraint('UPDATED_AT IS NOT NULL', 'DIDS_FOLLOWED_EVENTS_UPD_NN'),
                                      {'mysql_engine': 'InnoDB'})

        # otherwise, proceed normally
        # pylint: disable=maybe-no-member
        return cls._table_args + (CheckConstraint('CREATED_AT IS NOT NULL', name=cls.__tablename__.upper() + '_CREATED_NN'),
                                  CheckConstraint('UPDATED_AT IS NOT NULL', name=cls.__tablename__.upper() + '_UPDATED_NN'),
                                  {'mysql_engine': 'InnoDB'})

    @declared_attr
    def created_at(cls):  # pylint: disable=no-self-argument
        return Column("created_at", DateTime, default=datetime.datetime.utcnow)

    @declared_attr
    def updated_at(cls):  # pylint: disable=no-self-argument
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
        for k, v in iteritems(values):
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

    def __next__(self):
        n = next(self._i).name
        return n, getattr(self, n)

    def keys(self):
        return list(self.__dict__.keys())

    def values(self):
        return list(self.__dict__.values())

    def items(self):
        return list(self.__dict__.items())

    def to_dict(self):
        return self.__dict__.copy()

    next = __next__


class SoftModelBase(ModelBase):
    """Base class for Rucio Models with soft-deletion support"""
    __table_initialized__ = False

    @declared_attr
    def __table_args__(cls):  # pylint: disable=no-self-argument
        # pylint: disable=maybe-no-member
        return cls._table_args + (CheckConstraint('CREATED_AT IS NOT NULL', name=cls.__tablename__.upper() + '_CREATED_NN'),
                                  CheckConstraint('UPDATED_AT IS NOT NULL', name=cls.__tablename__.upper() + '_UPDATED_NN'),
                                  CheckConstraint('DELETED IS NOT NULL', name=cls.__tablename__.upper() + '_DELETED_NN'),
                                  {'mysql_engine': 'InnoDB', 'info': {'soft_delete': True}})

    def delete(self, session=None):
        """Delete this object"""
        self.deleted = True
        self.deleted_at = datetime.datetime.utcnow()
        self.save(session=session)


class Account(BASE, ModelBase):
    """Represents an account"""
    __tablename__ = 'accounts'
    account = Column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    account_type = Column(AccountType.db_type(name='ACCOUNTS_TYPE_CHK'))
    status = Column(AccountStatus.db_type(default=AccountStatus.ACTIVE, name='ACCOUNTS_STATUS_CHK'))
    email = Column(String(255))
    suspended_at = Column(DateTime)
    deleted_at = Column(DateTime)
    _table_args = (PrimaryKeyConstraint('account', name='ACCOUNTS_PK'),
                   CheckConstraint('ACCOUNT_TYPE IS NOT NULL', name='ACCOUNTS_TYPE_NN'),
                   CheckConstraint('STATUS IS NOT NULL', name='ACCOUNTS_STATUS_NN'))


class AccountAttrAssociation(BASE, ModelBase):
    """Represents an account"""
    __tablename__ = 'account_attr_map'
    account = Column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    key = Column(String(255))
    value = Column(BooleanString(255))
    _table_args = (PrimaryKeyConstraint('account', 'key', name='ACCOUNT_ATTR_MAP_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='ACCOUNT_ATTR_MAP_ACCOUNT_FK'),
                   Index('ACCOUNT_ATTR_MAP_KEY_VALUE_IDX', 'key', 'value'))


class Identity(BASE, SoftModelBase):
    """Represents an identity"""
    __tablename__ = 'identities'
    identity = Column(String(2048))
    identity_type = Column(IdentityType.db_type(name='IDENTITIES_TYPE_CHK'))
    username = Column(String(255))
    password = Column(String(255))
    salt = Column(LargeBinary(255))
    email = Column(String(255))
    _table_args = (PrimaryKeyConstraint('identity', 'identity_type', name='IDENTITIES_PK'),
                   CheckConstraint('IDENTITY_TYPE IS NOT NULL', name='IDENTITIES_TYPE_NN'),
                   CheckConstraint('EMAIL IS NOT NULL', name='IDENTITIES_EMAIL_NN'))


class IdentityAccountAssociation(BASE, ModelBase):
    """Represents a map account-identity"""
    __tablename__ = 'account_map'
    identity = Column(String(2048))
    identity_type = Column(IdentityType.db_type(name='ACCOUNT_MAP_ID_TYPE_CHK'))
    account = Column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    is_default = Column(Boolean(name='ACCOUNT_MAP_DEFAULT_CHK'), default=False)
    _table_args = (PrimaryKeyConstraint('identity', 'identity_type', 'account', name='ACCOUNT_MAP_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='ACCOUNT_MAP_ACCOUNT_FK'),
                   ForeignKeyConstraint(['identity', 'identity_type'], ['identities.identity', 'identities.identity_type'], name='ACCOUNT_MAP_ID_TYPE_FK'),
                   CheckConstraint('is_default IS NOT NULL', name='ACCOUNT_MAP_IS_DEFAULT_NN'),
                   CheckConstraint('IDENTITY_TYPE IS NOT NULL', name='ACCOUNT_MAP_ID_TYPE_NN'))


class Scope(BASE, ModelBase):
    """Represents a scope"""
    __tablename__ = 'scopes'
    scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    account = Column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    is_default = Column(Boolean(name='SCOPES_DEFAULT_CHK'), default=False)
    status = Column(ScopeStatus.db_type(name='SCOPE_STATUS_CHK', default=ScopeStatus.OPEN))
    closed_at = Column(DateTime)
    deleted_at = Column(DateTime)
    _table_args = (PrimaryKeyConstraint('scope', name='SCOPES_SCOPE_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='SCOPES_ACCOUNT_FK'),
                   CheckConstraint('is_default IS NOT NULL', name='SCOPES_IS_DEFAULT_NN'),
                   CheckConstraint('STATUS IS NOT NULL', name='SCOPES_STATUS_NN'),
                   CheckConstraint('ACCOUNT IS NOT NULL', name='SCOPES_ACCOUNT_NN'))


class DataIdentifier(BASE, ModelBase):
    """Represents a dataset"""
    __tablename__ = 'dids'
    scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name = Column(String(get_schema_value('NAME_LENGTH')))
    account = Column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    did_type = Column(DIDType.db_type(name='DIDS_TYPE_CHK'))
    is_open = Column(Boolean(name='DIDS_IS_OPEN_CHK'))
    monotonic = Column(Boolean(name='DIDS_MONOTONIC_CHK'), server_default='0')
    hidden = Column(Boolean(name='DIDS_HIDDEN_CHK'), server_default='0')
    obsolete = Column(Boolean(name='DIDS_OBSOLETE_CHK'), server_default='0')
    complete = Column(Boolean(name='DIDS_COMPLETE_CHK'), server_default=None)
    is_new = Column(Boolean(name='DIDS_IS_NEW_CHK'), server_default='1')
    availability = Column(DIDAvailability.db_type(name='DIDS_AVAILABILITY_CHK'),
                          default=DIDAvailability.AVAILABLE)
    suppressed = Column(Boolean(name='FILES_SUPP_CHK'), server_default='0')
    bytes = Column(BigInteger)
    length = Column(BigInteger)
    md5 = Column(String(32))
    adler32 = Column(String(8))
    expired_at = Column(DateTime)
    purge_replicas = Column(Boolean(name='DIDS_PURGE_RPLCS_CHK'), server_default='1')
    deleted_at = Column(DateTime)
    # hardcoded meta-data to populate the db
    events = Column(BigInteger)
    guid = Column(GUID())
    project = Column(String(50))
    datatype = Column(String(50))
    run_number = Column(Integer)
    stream_name = Column(String(70))
    prod_step = Column(String(50))
    version = Column(String(50))
    campaign = Column(String(50))
    task_id = Column(Integer())
    panda_id = Column(Integer())
    lumiblocknr = Column(Integer())
    provenance = Column(String(2))
    phys_group = Column(String(25))
    transient = Column(Boolean(name='DID_TRANSIENT_CHK'), server_default='0')
    accessed_at = Column(DateTime)
    closed_at = Column(DateTime)
    eol_at = Column(DateTime)
    is_archive = Column(Boolean(name='DIDS_ARCHIVE_CHK'))
    constituent = Column(Boolean(name='DIDS_CONSTITUENT_CHK'))
    access_cnt = Column(Integer())
    _table_args = (PrimaryKeyConstraint('scope', 'name', name='DIDS_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], ondelete='CASCADE', name='DIDS_ACCOUNT_FK'),
                   ForeignKeyConstraint(['scope'], ['scopes.scope'], name='DIDS_SCOPE_FK'),
                   CheckConstraint('MONOTONIC IS NOT NULL', name='DIDS_MONOTONIC_NN'),
                   CheckConstraint('OBSOLETE IS NOT NULL', name='DIDS_OBSOLETE_NN'),
                   CheckConstraint('SUPPRESSED IS NOT NULL', name='DIDS_SUPP_NN'),
                   CheckConstraint('ACCOUNT IS NOT NULL', name='DIDS_ACCOUNT_NN'),
                   CheckConstraint('PURGE_REPLICAS IS NOT NULL', name='DIDS_PURGE_REPLICAS_NN'),
                   # UniqueConstraint('guid', name='DIDS_GUID_UQ'),
                   Index('DIDS_IS_NEW_IDX', 'is_new'),
                   Index('DIDS_EXPIRED_AT_IDX', 'expired_at'))


class DidMeta(BASE, ModelBase):
    __tablename__ = 'did_meta'
    scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name = Column(String(get_schema_value('NAME_LENGTH')))
    meta = Column(JSON())
    _table_args = (PrimaryKeyConstraint('scope', 'name', name='DID_META_PK'),
                   ForeignKeyConstraint(['scope', 'name'], ['dids.scope', 'dids.name'], name='DID_META_FK'),)


class DeletedDataIdentifier(BASE, ModelBase):
    """Represents a dataset"""
    __tablename__ = 'deleted_dids'
    scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name = Column(String(get_schema_value('NAME_LENGTH')))
    account = Column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    did_type = Column(DIDType.db_type(name='DEL_DIDS_TYPE_CHK'))
    is_open = Column(Boolean(name='DEL_DIDS_IS_OPEN_CHK'))
    monotonic = Column(Boolean(name='DEL_DIDS_MONO_CHK'), server_default='0')
    hidden = Column(Boolean(name='DEL_DIDS_HIDDEN_CHK'), server_default='0')
    obsolete = Column(Boolean(name='DEL_DIDS_OBSOLETE_CHK'), server_default='0')
    complete = Column(Boolean(name='DEL_DIDS_COMPLETE_CHK'))
    is_new = Column(Boolean(name='DEL_DIDS_IS_NEW_CHK'), server_default='1')
    availability = Column(DIDAvailability.db_type(name='DEL_DIDS_AVAIL_CHK'),
                          default=DIDAvailability.AVAILABLE)
    suppressed = Column(Boolean(name='DEL_FILES_SUPP_CHK'), server_default='0')
    bytes = Column(BigInteger)
    length = Column(BigInteger)
    md5 = Column(String(32))
    adler32 = Column(String(8))
    expired_at = Column(DateTime)
    deleted_at = Column(DateTime)
    events = Column(BigInteger)
    guid = Column(GUID())
    project = Column(String(50))
    datatype = Column(String(50))
    run_number = Column(Integer)
    stream_name = Column(String(70))
    prod_step = Column(String(50))
    version = Column(String(50))
    campaign = Column(String(50))
    task_id = Column(Integer())
    panda_id = Column(Integer())
    lumiblocknr = Column(Integer())
    provenance = Column(String(2))
    phys_group = Column(String(25))
    transient = Column(Boolean(name='DEL_DID_TRANSIENT_CHK'), server_default='0')
    purge_replicas = Column(Boolean(name='DELETED_DIDS_PURGE_RPLCS_CHK'))
    accessed_at = Column(DateTime)
    closed_at = Column(DateTime)
    eol_at = Column(DateTime)
    is_archive = Column(Boolean(name='DEL_DIDS_ARCH_CHK'))
    constituent = Column(Boolean(name='DEL_DIDS_CONST_CHK'))
    access_cnt = Column(Integer())
    _table_args = (PrimaryKeyConstraint('scope', 'name', name='DELETED_DIDS_PK'), )


class UpdatedDID(BASE, ModelBase):
    """Represents the recently updated dids"""
    __tablename__ = 'updated_dids'
    id = Column(GUID(), default=utils.generate_uuid)
    scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name = Column(String(get_schema_value('NAME_LENGTH')))
    rule_evaluation_action = Column(DIDReEvaluation.db_type(name='UPDATED_DIDS_RULE_EVAL_ACT_CHK'))
    _table_args = (PrimaryKeyConstraint('id', name='UPDATED_DIDS_PK'),
                   CheckConstraint('SCOPE IS NOT NULL', name='UPDATED_DIDS_SCOPE_NN'),
                   CheckConstraint('NAME IS NOT NULL', name='UPDATED_DIDS_NAME_NN'),
                   Index('UPDATED_DIDS_SCOPERULENAME_IDX', 'scope', 'rule_evaluation_action', 'name'))


class BadReplicas(BASE, ModelBase):
    """Represents the suspicious or bad replicas"""
    __tablename__ = 'bad_replicas'
    scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name = Column(String(get_schema_value('NAME_LENGTH')))
    rse_id = Column(GUID())
    reason = Column(String(255))
    state = Column(BadFilesStatus.db_type(name='BAD_REPLICAS_STATE_CHK'), default=BadFilesStatus.SUSPICIOUS)
    account = Column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    bytes = Column(BigInteger)
    expires_at = Column(DateTime)
    _table_args = (PrimaryKeyConstraint('scope', 'name', 'rse_id', 'state', 'created_at', name='BAD_REPLICAS_STATE_PK'),
                   CheckConstraint('SCOPE IS NOT NULL', name='BAD_REPLICAS_SCOPE_NN'),
                   CheckConstraint('NAME IS NOT NULL', name='BAD_REPLICAS_NAME_NN'),
                   CheckConstraint('RSE_ID IS NOT NULL', name='BAD_REPLICAS_RSE_ID_NN'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='BAD_REPLICAS_ACCOUNT_FK'),
                   Index('BAD_REPLICAS_STATE_IDX', 'rse_id', 'state'),
                   Index('BAD_REPLICAS_EXPIRES_AT_IDX', 'expires_at'))


class BadPFNs(BASE, ModelBase):
    """Represents bad, suspicious or temporary unavailable PFNs which have to be processed and added to BadReplicas Table"""
    __tablename__ = 'bad_pfns'
    path = Column(String(2048))  # PREFIX + PFN
    state = Column(BadPFNStatus.db_type(name='BAD_PFNS_STATE_CHK'), default=BadPFNStatus.SUSPICIOUS)
    reason = Column(String(255))
    account = Column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    expires_at = Column(DateTime)
    _table_args = (PrimaryKeyConstraint('path', 'state', name='BAD_PFNS_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='BAD_PFNS_ACCOUNT_FK'))


class QuarantinedReplica(BASE, ModelBase, Versioned):
    """Represents the quarantined replicas"""
    __tablename__ = 'quarantined_replicas'
    rse_id = Column(GUID())
    path = Column(String(1024))
    bytes = Column(BigInteger)
    md5 = Column(String(32))
    adler32 = Column(String(8))
    scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name = Column(String(get_schema_value('NAME_LENGTH')))
    _table_args = (PrimaryKeyConstraint('rse_id', 'path', name='QURD_REPLICAS_STATE_PK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='QURD_REPLICAS_RSE_ID_FK'),
                   Index('QUARANTINED_REPLICAS_PATH_IDX', 'path', 'rse_id', unique=True))


class DIDKey(BASE, ModelBase):
    """Represents Data IDentifier property keys"""
    __tablename__ = 'did_keys'
    key = Column(String(255))
    is_enum = Column(Boolean(name='DID_KEYS_IS_ENUM_CHK'), server_default='0')
    key_type = Column(KeyType.db_type(name='DID_KEYS_TYPE_CHK'))
    value_type = Column(String(255))
    value_regexp = Column(String(255))
    _table_args = (PrimaryKeyConstraint('key', name='DID_KEYS_PK'),
                   CheckConstraint('key_type IS NOT NULL', name='DID_KEYS_TYPE_NN'),
                   CheckConstraint('is_enum IS NOT NULL', name='DID_KEYS_IS_ENUM_NN'))


class DIDKeyValueAssociation(BASE, ModelBase):
    """Represents Data IDentifier property key/values"""
    __tablename__ = 'did_key_map'
    key = Column(String(255))
    value = Column(String(255))
    _table_args = (PrimaryKeyConstraint('key', 'value', name='DID_KEY_MAP_PK'),
                   ForeignKeyConstraint(['key'], ['did_keys.key'], name='DID_MAP_KEYS_FK'))


class DataIdentifierAssociation(BASE, ModelBase):
    """Represents the map between containers/datasets and files"""
    __tablename__ = 'contents'
    scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))  # dataset scope
    name = Column(String(get_schema_value('NAME_LENGTH')))    # dataset name
    child_scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))  # Provenance scope
    child_name = Column(String(get_schema_value('NAME_LENGTH')))    # Provenance name
    did_type = Column(DIDType.db_type(name='CONTENTS_DID_TYPE_CHK'))
    child_type = Column(DIDType.db_type(name='CONTENTS_CHILD_TYPE_CHK'))
    bytes = Column(BigInteger)
    adler32 = Column(String(8))
    md5 = Column(String(32))
    guid = Column(GUID())
    events = Column(BigInteger)
    rule_evaluation = Column(Boolean(name='CONTENTS_RULE_EVALUATION_CHK'))
    _table_args = (PrimaryKeyConstraint('scope', 'name', 'child_scope', 'child_name', name='CONTENTS_PK'),
                   ForeignKeyConstraint(['scope', 'name'], ['dids.scope', 'dids.name'], name='CONTENTS_ID_FK'),
                   ForeignKeyConstraint(['child_scope', 'child_name'], ['dids.scope', 'dids.name'], ondelete="CASCADE", name='CONTENTS_CHILD_ID_FK'),
                   CheckConstraint('DID_TYPE IS NOT NULL', name='CONTENTS_DID_TYPE_NN'),
                   CheckConstraint('CHILD_TYPE IS NOT NULL', name='CONTENTS_CHILD_TYPE_NN'),
                   Index('CONTENTS_CHILD_SCOPE_NAME_IDX', 'child_scope', 'child_name', 'scope', 'name'))


class ConstituentAssociation(BASE, ModelBase):
    """Represents the map between archives and constituents"""
    __tablename__ = 'archive_contents'
    child_scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))    # Constituent file scope
    child_name = Column(String(get_schema_value('NAME_LENGTH')))    # Constituent file name
    scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))          # Archive file scope
    name = Column(String(get_schema_value('NAME_LENGTH')))          # Archive file name
    bytes = Column(BigInteger)
    adler32 = Column(String(8))
    md5 = Column(String(32))
    guid = Column(GUID())
    length = Column(BigInteger)
    _table_args = (PrimaryKeyConstraint('child_scope', 'child_name', 'scope', 'name',
                                        name='ARCH_CONTENTS_PK'),
                   ForeignKeyConstraint(['scope', 'name'], ['dids.scope', 'dids.name'],
                                        name='ARCH_CONTENTS_PARENT_FK'),
                   ForeignKeyConstraint(['child_scope', 'child_name'],
                                        ['dids.scope', 'dids.name'], ondelete="CASCADE",
                                        name='ARCH_CONTENTS_CHILD_FK'),
                   Index('ARCH_CONTENTS_CHILD_IDX', 'scope', 'name',
                         'child_scope', 'child_name', ))


class ConstituentAssociationHistory(BASE, ModelBase):
    """Represents the map between archives and constituents"""
    __tablename__ = 'archive_contents_history'
    child_scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))    # Constituent file scope
    child_name = Column(String(get_schema_value('NAME_LENGTH')))    # Constituent file name
    scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))          # Archive file scope
    name = Column(String(get_schema_value('NAME_LENGTH')))  # Archive file name
    bytes = Column(BigInteger)
    adler32 = Column(String(8))
    md5 = Column(String(32))
    guid = Column(GUID())
    length = Column(BigInteger)
    __mapper_args__ = {
        'primary_key': [scope, name, child_scope, child_name]  # Fake primary key for SQLA
    }
    _table_args = (Index('ARCH_CONT_HIST_IDX', 'scope', 'name'), )
    # _table_args = (PrimaryKeyConstraint('scope', 'name', 'child_scope', 'child_name',
    #                                     name='ARCH_CONTENTS_HISOTRY_PK'), )


class DataIdentifierAssociationHistory(BASE, ModelBase):
    """Represents the map history between containers/datasets and files"""
    __tablename__ = 'contents_history'
    scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))          # dataset scope
    name = Column(String(get_schema_value('NAME_LENGTH')))  # dataset name
    child_scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))          # Provenance scope
    child_name = Column(String(get_schema_value('NAME_LENGTH')))  # Provenance name
    did_type = Column(DIDType.db_type(name='CONTENTS_HIST_DID_TYPE_CHK'))
    child_type = Column(DIDType.db_type(name='CONTENTS_HIST_CHILD_TYPE_CHK'))
    bytes = Column(BigInteger)
    adler32 = Column(String(8))
    md5 = Column(String(32))
    guid = Column(GUID())
    events = Column(BigInteger)
    rule_evaluation = Column(Boolean(name='CONTENTS_HIST_RULE_EVAL_CHK'))
    did_created_at = Column(DateTime)
    deleted_at = Column(DateTime)
    __mapper_args__ = {
        'primary_key': [scope, name, child_scope, child_name]  # Fake primary key for SQLA
    }
    # _table_args = (PrimaryKeyConstraint('scope', 'name', 'child_scope', 'child_name', name='CONTENTS_HIST_PK'),
    _table_args = (CheckConstraint('DID_TYPE IS NOT NULL', name='CONTENTS_HIST_DID_TYPE_NN'),
                   CheckConstraint('CHILD_TYPE IS NOT NULL', name='CONTENTS_HIST_CHILD_TYPE_NN'),
                   Index('CONTENTS_HISTORY_IDX', 'scope', 'name'))


class RSE(BASE, SoftModelBase):
    """Represents a Rucio Location"""
    __tablename__ = 'rses'
    id = Column(GUID(), default=utils.generate_uuid)
    rse = Column(String(255))
    vo = Column(String(3), nullable=False, server_default='def')
    rse_type = Column(RSEType.db_type(name='RSES_TYPE_CHK'), default=RSEType.DISK)
    deterministic = Column(Boolean(name='RSE_DETERMINISTIC_CHK'), default=True)
    volatile = Column(Boolean(name='RSE_VOLATILE_CHK'), default=False)
    staging_area = Column(Boolean(name='RSE_STAGING_AREA_CHK'), default=False)
    city = Column(String(255))
    region_code = Column(String(2))
    country_name = Column(String(255))
    continent = Column(String(2))
    time_zone = Column(String(255))
    ISP = Column(String(255))
    ASN = Column(String(255))
    longitude = Column(Float())
    latitude = Column(Float())
    availability = Column(Integer, server_default='7')
    usage = relationship("RSEUsage", order_by="RSEUsage.rse_id", backref="rses")
    qos_class = Column(String(64))
    _table_args = (PrimaryKeyConstraint('id', name='RSES_PK'),
                   UniqueConstraint('rse', 'vo', name='RSES_RSE_UQ'),
                   CheckConstraint('RSE IS NOT NULL', name='RSES_RSE__NN'),
                   CheckConstraint('RSE_TYPE IS NOT NULL', name='RSES_TYPE_NN'),
                   ForeignKeyConstraint(['vo'], ['vos.vo'], name='RSES_VOS_FK'), )


class RSELimit(BASE, ModelBase):
    """Represents RSE limits"""
    __tablename__ = 'rse_limits'
    rse_id = Column(GUID())
    name = Column(String(255))
    value = Column(BigInteger)
    _table_args = (PrimaryKeyConstraint('rse_id', 'name', name='RSE_LIMITS_PK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='RSE_LIMIT_RSE_ID_FK'), )


class RSETransferLimit(BASE, ModelBase):
    """Represents RSE limits"""
    __tablename__ = 'rse_transfer_limits'
    rse_id = Column(GUID())
    activity = Column(String(50))
    rse_expression = Column(String(3000))
    max_transfers = Column(BigInteger)
    volume = Column(BigInteger)
    deadline = Column(BigInteger)
    strategy = Column(String(25))
    direction = Column(String(25))
    transfers = Column(BigInteger)
    waitings = Column(BigInteger)
    _table_args = (PrimaryKeyConstraint('rse_id', 'activity', name='RSE_TRANSFER_LIMITS_PK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='RSE_TRANSFER_LIMITS_RSE_ID_FK'), )


class RSEUsage(BASE, ModelBase, Versioned):
    """Represents location usage"""
    __tablename__ = 'rse_usage'
    rse_id = Column(GUID())
    source = Column(String(255))
    used = Column(BigInteger)
    free = Column(BigInteger)
    files = Column(BigInteger)
    rse = relationship("RSE", backref=backref('rse_usage', order_by=rse_id))
    _table_args = (PrimaryKeyConstraint('rse_id', 'source', name='RSE_USAGE_PK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='RSE_USAGE_RSE_ID_FK'), )


class UpdatedRSECounter(BASE, ModelBase):
    """Represents the recently updated RSE counters"""
    __tablename__ = 'updated_rse_counters'
    id = Column(GUID(), default=utils.generate_uuid)
    rse_id = Column(GUID())
    files = Column(BigInteger)
    bytes = Column(BigInteger)
    _table_args = (PrimaryKeyConstraint('id', name='UPDATED_RSE_CNTRS_PK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='UPDATED_RSE_CNTRS_RSE_ID_FK'),
                   Index('UPDATED_RSE_CNTRS_RSE_ID_IDX', 'rse_id'))


class RSEAttrAssociation(BASE, ModelBase):
    """Represents the map between RSEs and tags"""
    __tablename__ = 'rse_attr_map'
    rse_id = Column(GUID())
    key = Column(String(255))
    value = Column(BooleanString(255))
    rse = relationship("RSE", backref=backref('rse_attr_map', order_by=rse_id))
    _table_args = (PrimaryKeyConstraint('rse_id', 'key', name='RSE_ATTR_MAP_PK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='RSE_ATTR_MAP_RSE_ID_FK'),
                   Index('RSE_ATTR_MAP_KEY_VALUE_IDX', 'key', 'value'))


class RSEProtocols(BASE, ModelBase):
    """Represents supported protocols of RSEs (Rucio Storage Elements)"""
    __tablename__ = 'rse_protocols'
    rse_id = Column(GUID())
    scheme = Column(String(255))
    hostname = Column(String(255), server_default='')  # For protocol without host e.g. POSIX on local file systems localhost is assumed as beeing default
    port = Column(Integer, server_default='0')  # like host, for local protocol the port 0 is assumed to be default
    prefix = Column(String(1024), nullable=True)
    impl = Column(String(255), nullable=False)
    read_lan = Column(Integer, server_default='0')  # if no value is provided, 0 i.e. not supported is assumed as default value
    write_lan = Column(Integer, server_default='0')  # if no value is provided, 0 i.e. not supported is assumed as default value
    delete_lan = Column(Integer, server_default='0')  # if no value is provided, 0 i.e. not supported is assumed as default value
    read_wan = Column(Integer, server_default='0')  # if no value is provided, 0 i.e. not supported is assumed as default value
    write_wan = Column(Integer, server_default='0')  # if no value is provided, 0 i.e. not supported is assumed as default value
    delete_wan = Column(Integer, server_default='0')  # if no value is provided, 0 i.e. not supported is assumed as default value
    third_party_copy = Column(Integer, server_default='0')  # if no value is provided, 0 i.e. not supported is assumed as default value
    third_party_copy_read = Column(Integer, server_default='0')  # if no value is provided, 0 i.e. not supported is assumed as default value
    third_party_copy_write = Column(Integer, server_default='0')  # if no value is provided, 0 i.e. not supported is assumed as default value
    extended_attributes = Column(String(4000), nullable=True)
    rses = relationship("RSE", backref="rse_protocols")
    _table_args = (PrimaryKeyConstraint('rse_id', 'scheme', 'hostname', 'port', name='RSE_PROTOCOL_PK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='RSE_PROTOCOL_RSE_ID_FK'),
                   CheckConstraint('IMPL IS NOT NULL', name='RSE_PROTOCOLS_IMPL_NN'))


class RSEQoSAssociation(BASE, ModelBase):
    """Represents the mapping of RSEs"""
    __tablename__ = 'rse_qos_map'
    rse_id = Column(GUID())
    qos_policy = Column(String(64))
    _table_args = (PrimaryKeyConstraint('rse_id', 'qos_policy', name='RSE_QOS_MAP_PK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='RSE_QOS_MAP_RSE_ID_FK'))


class AccountLimit(BASE, ModelBase):
    """Represents account limits"""
    __tablename__ = 'account_limits'
    account = Column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    rse_id = Column(GUID())
    bytes = Column(BigInteger)
    _table_args = (PrimaryKeyConstraint('account', 'rse_id', name='ACCOUNT_LIMITS_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='ACCOUNT_LIMITS_ACCOUNT_FK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='ACCOUNT_LIMITS_RSE_ID_FK'),)


class AccountGlobalLimit(BASE, ModelBase):
    """Represents account limits"""
    __tablename__ = 'account_glob_limits'
    account = Column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    rse_expression = Column(String(3000))
    bytes = Column(BigInteger)
    _table_args = (PrimaryKeyConstraint('account', 'rse_expression', name='ACCOUNT_GLOBAL_LIMITS_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='ACCOUNT_GLOBAL_LIMITS_ACC_FK'),)


class AccountUsage(BASE, ModelBase, Versioned):
    """Represents account usage"""
    __tablename__ = 'account_usage'
    account = Column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    rse_id = Column(GUID())
    files = Column(BigInteger)
    bytes = Column(BigInteger)
    _table_args = (PrimaryKeyConstraint('account', 'rse_id', name='ACCOUNT_USAGE_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='ACCOUNT_USAGE_ACCOUNT_FK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='ACCOUNT_USAGE_RSES_ID_FK'), )


class RSEFileAssociation(BASE, ModelBase):
    """Represents the map between locations and files"""
    __tablename__ = 'replicas'
    rse_id = Column(GUID())
    scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name = Column(String(get_schema_value('NAME_LENGTH')))
    bytes = Column(BigInteger)
    md5 = Column(String(32))
    adler32 = Column(String(8))
    path = Column(String(1024))
    state = Column(ReplicaState.db_type(name='REPLICAS_STATE_CHK'), default=ReplicaState.UNAVAILABLE)
    lock_cnt = Column(Integer, server_default='0')
    accessed_at = Column(DateTime)
    tombstone = Column(DateTime)
    rse = relationship("RSE", backref=backref('replicas', order_by="RSE.id"))
    _table_args = (PrimaryKeyConstraint('scope', 'name', 'rse_id', name='REPLICAS_PK'),
                   ForeignKeyConstraint(['scope', 'name'], ['dids.scope', 'dids.name'], name='REPLICAS_LFN_FK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='REPLICAS_RSE_ID_FK'),
                   CheckConstraint('STATE IS NOT NULL', name='REPLICAS_STATE_NN'),
                   CheckConstraint('bytes IS NOT NULL', name='REPLICAS_SIZE_NN'),
                   CheckConstraint('lock_cnt IS NOT NULL', name='REPLICAS_LOCK_CNT_NN'),
                   Index('REPLICAS_TOMBSTONE_IDX', 'tombstone'),
                   Index('REPLICAS_PATH_IDX', 'path', mysql_length=get_schema_value('NAME_LENGTH')))


class CollectionReplica(BASE, ModelBase):
    """Represents replicas for datasets/collections"""
    __tablename__ = 'collection_replicas'
    scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name = Column(String(get_schema_value('NAME_LENGTH')))
    did_type = Column(DIDType.db_type(name='COLLECTION_REPLICAS_TYPE_CHK'))
    rse_id = Column(GUID())
    bytes = Column(BigInteger)
    length = Column(BigInteger)
    available_bytes = Column(BigInteger)
    available_replicas_cnt = Column(BigInteger)
    state = Column(ReplicaState.db_type(name='COLLECTION_REPLICAS_STATE_CHK'), default=ReplicaState.UNAVAILABLE)
    accessed_at = Column(DateTime)
    _table_args = (PrimaryKeyConstraint('scope', 'name', 'rse_id', name='COLLECTION_REPLICAS_PK'),
                   ForeignKeyConstraint(['scope', 'name'], ['dids.scope', 'dids.name'], name='COLLECTION_REPLICAS_LFN_FK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='COLLECTION_REPLICAS_RSE_ID_FK'),
                   CheckConstraint('STATE IS NOT NULL', name='COLLECTION_REPLICAS_STATE_NN'),
                   CheckConstraint('bytes IS NOT NULL', name='COLLECTION_REPLICAS_SIZE_NN'),
                   Index('COLLECTION_REPLICAS_RSE_ID_IDX', 'rse_id'))


class UpdatedCollectionReplica(BASE, ModelBase):
    """Represents updates to replicas for datasets/collections"""
    __tablename__ = 'updated_col_rep'
    id = Column(GUID(), default=utils.generate_uuid)
    scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name = Column(String(get_schema_value('NAME_LENGTH')))
    did_type = Column(DIDType.db_type(name='UPDATED_COL_REP_TYPE_CHK'))
    rse_id = Column(GUID())
    _table_args = (PrimaryKeyConstraint('id', name='UPDATED_COL_REP_PK'),
                   CheckConstraint('SCOPE IS NOT NULL', name='UPDATED_COL_REP_SCOPE_NN'),
                   CheckConstraint('NAME IS NOT NULL', name='UPDATED_COL_REP_NAME_NN'),
                   Index('UPDATED_COL_REP_SNR_IDX', 'scope', 'name', 'rse_id'))


class RSEFileAssociationHistory(BASE, ModelBase):
    """Represents a short history of the deleted replicas"""
    __tablename__ = 'replicas_history'
    rse_id = Column(GUID())
    scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name = Column(String(get_schema_value('NAME_LENGTH')))
    bytes = Column(BigInteger)
    _table_args = (PrimaryKeyConstraint('rse_id', 'scope', 'name', name='REPLICAS_HIST_PK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='REPLICAS_HIST_RSE_ID_FK'),
                   CheckConstraint('bytes IS NOT NULL', name='REPLICAS_HIST_SIZE_NN'))
#  ForeignKeyConstraint(['scope', 'name'], ['dids.scope', 'dids.name'], name='REPLICAS_HIST_LFN_FK'),


class ReplicationRule(BASE, ModelBase):
    """Represents data identifier replication rules"""
    __tablename__ = 'rules'
    id = Column(GUID(), default=utils.generate_uuid)
    subscription_id = Column(GUID())
    account = Column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name = Column(String(get_schema_value('NAME_LENGTH')))
    did_type = Column(DIDType.db_type(name='RULES_DID_TYPE_CHK'))
    state = Column(RuleState.db_type(name='RULES_STATE_CHK'), default=RuleState.REPLICATING)
    error = Column(String(255))
    rse_expression = Column(String(3000))
    copies = Column(SmallInteger, server_default='1')
    expires_at = Column(DateTime)
    weight = Column(String(255))
    locked = Column(Boolean(name='RULES_LOCKED_CHK'), default=False)
    locks_ok_cnt = Column(BigInteger, server_default='0')
    locks_replicating_cnt = Column(BigInteger, server_default='0')
    locks_stuck_cnt = Column(BigInteger, server_default='0')
    source_replica_expression = Column(String(255))
    activity = Column(String(50), default='default')
    grouping = Column(RuleGrouping.db_type(name='RULES_GROUPING_CHK'), default=RuleGrouping.ALL)
    notification = Column(RuleNotification.db_type(name='RULES_NOTIFICATION_CHK'), default=RuleNotification.NO)
    stuck_at = Column(DateTime)
    purge_replicas = Column(Boolean(name='RULES_PURGE_REPLICAS_CHK'), default=False)
    ignore_availability = Column(Boolean(name='RULES_IGNORE_AVAILABILITY_CHK'), default=False)
    ignore_account_limit = Column(Boolean(name='RULES_IGNORE_ACCOUNT_LIMIT_CHK'), default=False)
    priority = Column(Integer)
    comments = Column(String(255))
    child_rule_id = Column(GUID())
    eol_at = Column(DateTime)
    split_container = Column(Boolean(name='RULES_SPLIT_CONTAINER_CHK'), default=False)
    meta = Column(String(4000))
    _table_args = (PrimaryKeyConstraint('id', name='RULES_PK'),
                   ForeignKeyConstraint(['scope', 'name'], ['dids.scope', 'dids.name'], name='RULES_SCOPE_NAME_FK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='RULES_ACCOUNT_FK'),
                   ForeignKeyConstraint(['subscription_id'], ['subscriptions.id'], name='RULES_SUBS_ID_FK'),
                   ForeignKeyConstraint(['child_rule_id'], ['rules.id'], name='RULES_CHILD_RULE_ID_FK'),
                   CheckConstraint('STATE IS NOT NULL', name='RULES_STATE_NN'),
                   CheckConstraint('SCOPE IS NOT NULL', name='RULES_SCOPE_NN'),
                   CheckConstraint('NAME IS NOT NULL', name='RULES_NAME_NN'),
                   CheckConstraint(grouping != None, name='RULES_GROUPING_NN'),  # NOQA: E711
                   CheckConstraint('COPIES IS NOT NULL', name='RULES_COPIES_NN'),
                   CheckConstraint('LOCKED IS NOT NULL', name='RULES_LOCKED_NN'),
                   CheckConstraint('ACCOUNT IS NOT NULL', name='RULES_ACCOUNT_NN'),
                   CheckConstraint('LOCKS_OK_CNT IS NOT NULL', name='RULES_LOCKS_OK_CNT_NN'),
                   CheckConstraint('LOCKS_REPLICATING_CNT IS NOT NULL', name='RULES_LOCKS_REPLICATING_CNT_NN'),
                   CheckConstraint('LOCKS_STUCK_CNT IS NOT NULL', name='RULES_LOCKS_STUCK_CNT_NN'),
                   CheckConstraint('PURGE_REPLICAS IS NOT NULL', name='RULES_PURGE_REPLICAS_NN'),
                   Index('RULES_SC_NA_AC_RS_CO_UQ_IDX', 'scope', 'name', 'account', 'rse_expression', 'copies',
                         unique=True, mysql_length={'rse_expression': 767}),
                   Index('RULES_SCOPE_NAME_IDX', 'scope', 'name'),
                   Index('RULES_EXPIRES_AT_IDX', 'expires_at'),
                   Index('RULES_STUCKSTATE_IDX', 'state'),  # This Index is only needed for the STUCK state
                   Index('RULES_CHILD_RULE_ID_IDX', 'child_rule_id'))


class ReplicationRuleHistoryRecent(BASE, ModelBase):
    """Represents replication rules in the recent history"""
    __tablename__ = 'rules_hist_recent'
    id = Column(GUID())
    subscription_id = Column(GUID())
    account = Column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name = Column(String(get_schema_value('NAME_LENGTH')))
    did_type = Column(DIDType.db_type(name='RULES_HIST_RECENT_DIDTYPE_CHK'))
    state = Column(RuleState.db_type(name='RULES_HIST_RECENT_STATE_CHK'))
    error = Column(String(255))
    rse_expression = Column(String(3000))
    copies = Column(SmallInteger)
    expires_at = Column(DateTime)
    weight = Column(String(255))
    locked = Column(Boolean())
    locks_ok_cnt = Column(BigInteger)
    locks_replicating_cnt = Column(BigInteger)
    locks_stuck_cnt = Column(BigInteger)
    source_replica_expression = Column(String(255))
    activity = Column(String(50))
    grouping = Column(RuleGrouping.db_type(name='RULES_HIST_RECENT_GROUPING_CHK'))
    notification = Column(RuleNotification.db_type(name='RULES_HIST_RECENT_NOTIFY_CHK'))
    stuck_at = Column(DateTime)
    purge_replicas = Column(Boolean())
    ignore_availability = Column(Boolean())
    ignore_account_limit = Column(Boolean())
    priority = Column(Integer)
    comments = Column(String(255))
    child_rule_id = Column(GUID())
    eol_at = Column(DateTime)
    split_container = Column(Boolean())
    meta = Column(String(4000))
    __mapper_args__ = {
        'primary_key': [id, locks_replicating_cnt]  # Fake primary key for SQLA
    }
    _table_args = (Index('RULES_HIST_RECENT_ID_IDX', 'id'),
                   Index('RULES_HIST_RECENT_SC_NA_IDX', 'scope', 'name'))


class ReplicationRuleHistory(BASE, ModelBase):
    """Represents replication rules in the longterm history"""
    __tablename__ = 'rules_history'
    id = Column(GUID())
    subscription_id = Column(GUID())
    account = Column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name = Column(String(get_schema_value('NAME_LENGTH')))
    did_type = Column(DIDType.db_type(name='RULES_HISTORY_DIDTYPE_CHK'))
    state = Column(RuleState.db_type(name='RULES_HISTORY_STATE_CHK'))
    error = Column(String(255))
    rse_expression = Column(String(3000))
    copies = Column(SmallInteger)
    expires_at = Column(DateTime)
    weight = Column(String(255))
    locked = Column(Boolean())
    locks_ok_cnt = Column(BigInteger)
    locks_replicating_cnt = Column(BigInteger)
    locks_stuck_cnt = Column(BigInteger)
    source_replica_expression = Column(String(255))
    activity = Column(String(50))
    grouping = Column(RuleGrouping.db_type(name='RULES_HISTORY_GROUPING_CHK'))
    notification = Column(RuleNotification.db_type(name='RULES_HISTORY_NOTIFY_CHK'))
    stuck_at = Column(DateTime)
    priority = Column(Integer)
    purge_replicas = Column(Boolean())
    ignore_availability = Column(Boolean())
    ignore_account_limit = Column(Boolean())
    comments = Column(String(255))
    child_rule_id = Column(GUID())
    eol_at = Column(DateTime)
    split_container = Column(Boolean())
    meta = Column(String(4000))
    __mapper_args__ = {
        'primary_key': [id, locks_replicating_cnt]  # Fake primary key for SQLA
    }
    _table_args = (Index('RULES_HISTORY_SCOPENAME_IDX', 'scope', 'name'), )


class ReplicaLock(BASE, ModelBase):
    """Represents replica locks"""
    __tablename__ = 'locks'
    scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name = Column(String(get_schema_value('NAME_LENGTH')))
    rule_id = Column(GUID())
    rse_id = Column(GUID())
    account = Column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    bytes = Column(BigInteger)
    state = Column(LockState.db_type(name='LOCKS_STATE_CHK'), default=LockState.REPLICATING)
    repair_cnt = Column(BigInteger)
    _table_args = (PrimaryKeyConstraint('scope', 'name', 'rule_id', 'rse_id', name='LOCKS_PK'),
                   # ForeignKeyConstraint(['rse_id', 'scope', 'name'], ['replicas.rse_id', 'replicas.scope', 'replicas.name'], name='LOCKS_REPLICAS_FK'),
                   ForeignKeyConstraint(['rule_id'], ['rules.id'], name='LOCKS_RULE_ID_FK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='LOCKS_ACCOUNT_FK'),
                   CheckConstraint('STATE IS NOT NULL', name='LOCKS_STATE_NN'),
                   CheckConstraint('ACCOUNT IS NOT NULL', name='LOCKS_ACCOUNT_NN'),
                   Index('LOCKS_RULE_ID_IDX', 'rule_id'))


class DatasetLock(BASE, ModelBase):
    """Represents dataset locks"""
    __tablename__ = 'dataset_locks'
    scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name = Column(String(get_schema_value('NAME_LENGTH')))
    rule_id = Column(GUID())
    rse_id = Column(GUID())
    account = Column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    state = Column(LockState.db_type(name='DATASET_LOCKS_STATE_CHK'), default=LockState.REPLICATING)
    length = Column(BigInteger)
    bytes = Column(BigInteger)
    accessed_at = Column(DateTime)
    _table_args = (PrimaryKeyConstraint('scope', 'name', 'rule_id', 'rse_id', name='DATASET_LOCKS_PK'),
                   ForeignKeyConstraint(['scope', 'name'], ['dids.scope', 'dids.name'], name='DATASET_LOCKS_DID_FK'),
                   ForeignKeyConstraint(['rule_id'], ['rules.id'], name='DATASET_LOCKS_RULE_ID_FK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='DATASET_LOCKS_ACCOUNT_FK'),
                   CheckConstraint('STATE IS NOT NULL', name='DATASET_LOCKS_STATE_NN'),
                   CheckConstraint('ACCOUNT IS NOT NULL', name='DATASET_LOCKS_ACCOUNT_NN'),
                   Index('DATASET_LOCKS_RULE_ID_IDX', 'rule_id'),
                   Index('DATASET_LOCKS_RSE_ID_IDX', 'rse_id'))


class UpdatedAccountCounter(BASE, ModelBase):
    """Represents the recently updated Account counters"""
    __tablename__ = 'updated_account_counters'
    id = Column(GUID(), default=utils.generate_uuid)
    account = Column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    rse_id = Column(GUID())
    files = Column(BigInteger)
    bytes = Column(BigInteger)
    _table_args = (PrimaryKeyConstraint('id', name='UPDATED_ACCNT_CNTRS_PK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='UPDATED_ACCNT_CNTRS_RSE_ID_FK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='UPDATED_ACCNT_CNTRS_ACCOUNT_FK'),
                   Index('UPDATED_ACCNT_CNTRS_RSE_ID_IDX', 'account', 'rse_id'))


class Request(BASE, ModelBase, Versioned):
    """Represents a request for a single file with a third party service"""
    __tablename__ = 'requests'
    id = Column(GUID(), default=utils.generate_uuid)
    request_type = Column(RequestType.db_type(name='REQUESTS_TYPE_CHK'), default=RequestType.TRANSFER)
    scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name = Column(String(get_schema_value('NAME_LENGTH')))
    did_type = Column(DIDType.db_type(name='REQUESTS_DIDTYPE_CHK'), default=DIDType.FILE)
    dest_rse_id = Column(GUID())
    source_rse_id = Column(GUID())
    attributes = Column(String(4000))
    state = Column(RequestState.db_type(name='REQUESTS_STATE_CHK'), default=RequestState.QUEUED)
    external_id = Column(String(64))
    external_host = Column(String(256))
    retry_count = Column(Integer(), server_default='0')
    err_msg = Column(String(4000))
    previous_attempt_id = Column(GUID())
    rule_id = Column(GUID())
    activity = Column(String(50), default='default')
    bytes = Column(BigInteger)
    md5 = Column(String(32))
    adler32 = Column(String(8))
    dest_url = Column(String(2048))
    submitted_at = Column(DateTime)
    started_at = Column(DateTime)
    transferred_at = Column(DateTime)
    estimated_at = Column(DateTime)
    submitter_id = Column(Integer)
    estimated_started_at = Column(DateTime)
    estimated_transferred_at = Column(DateTime)
    staging_started_at = Column(DateTime)
    staging_finished_at = Column(DateTime)
    account = Column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    requested_at = Column(DateTime)
    priority = Column(Integer)
    _table_args = (PrimaryKeyConstraint('id', name='REQUESTS_PK'),
                   ForeignKeyConstraint(['scope', 'name'], ['dids.scope', 'dids.name'], name='REQUESTS_DID_FK'),
                   ForeignKeyConstraint(['dest_rse_id'], ['rses.id'], name='REQUESTS_RSES_FK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='REQUESTS_ACCOUNT_FK'),
                   CheckConstraint('dest_rse_id IS NOT NULL', name='REQUESTS_RSE_ID_NN'),
                   Index('REQUESTS_SCOPE_NAME_RSE_IDX', 'scope', 'name', 'dest_rse_id', 'request_type'),
                   Index('REQUESTS_TYP_STA_UPD_IDX_OLD', 'request_type', 'state', 'updated_at'),
                   Index('REQUESTS_TYP_STA_UPD_IDX', 'request_type', 'state', 'activity'),
                   Index('REQUESTS_RULEID_IDX', 'rule_id'),
                   Index('REQUESTS_EXTERNALID_UQ', 'external_id'))


class Source(BASE, ModelBase, Versioned):
    """Represents source files for transfers"""
    __tablename__ = 'sources'
    request_id = Column(GUID())
    scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name = Column(String(get_schema_value('NAME_LENGTH')))
    rse_id = Column(GUID())
    dest_rse_id = Column(GUID())
    url = Column(String(2048))
    bytes = Column(BigInteger)
    ranking = Column(Integer())
    is_using = Column(Boolean(), default=False)
    _table_args = (PrimaryKeyConstraint('request_id', 'rse_id', 'scope', 'name', name='SOURCES_PK'),
                   ForeignKeyConstraint(['request_id'], ['requests.id'], name='SOURCES_REQ_ID_FK'),
                   ForeignKeyConstraint(['scope', 'name', 'rse_id'], ['replicas.scope', 'replicas.name', 'replicas.rse_id'], name='SOURCES_REPLICA_FK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='SOURCES_RSES_FK'),
                   ForeignKeyConstraint(['dest_rse_id'], ['rses.id'], name='SOURCES_DEST_RSES_FK'),
                   Index('SOURCES_SRC_DST_IDX', 'rse_id', 'dest_rse_id'),
                   Index('SOURCES_SC_NM_DST_IDX', 'scope', 'rse_id', 'name'),
                   Index('SOURCES_DEST_RSEID_IDX', 'dest_rse_id'))


class Distance(BASE, ModelBase):
    """Represents distance between rses"""
    __tablename__ = 'distances'
    src_rse_id = Column(GUID())
    dest_rse_id = Column(GUID())
    ranking = Column(Integer())
    agis_distance = Column(Integer())
    geoip_distance = Column(Integer())
    active = Column(Integer())
    submitted = Column(Integer())
    finished = Column(Integer())
    failed = Column(Integer())
    transfer_speed = Column(Integer())
    packet_loss = Column(Integer())
    latency = Column(Integer())
    mbps_file = Column(Integer())
    mbps_link = Column(Integer())
    queued_total = Column(Integer())
    done_1h = Column(Integer())
    done_6h = Column(Integer())
    _table_args = (PrimaryKeyConstraint('src_rse_id', 'dest_rse_id', name='DISTANCES_PK'),
                   ForeignKeyConstraint(['src_rse_id'], ['rses.id'], name='DISTANCES_SRC_RSES_FK'),
                   ForeignKeyConstraint(['dest_rse_id'], ['rses.id'], name='DISTANCES_DEST_RSES_FK'),
                   Index('DISTANCES_DEST_RSEID_IDX', 'dest_rse_id'))


class Subscription(BASE, ModelBase, Versioned):
    """Represents a subscription"""
    __tablename__ = 'subscriptions'
    id = Column(GUID(), default=utils.generate_uuid)
    name = Column(String(64))
    filter = Column(String(2048))
    replication_rules = Column(String(1024))
    policyid = Column(SmallInteger, server_default='0')
    state = Column(SubscriptionState.db_type(name='SUBSCRIPTIONS_STATE_CHK', default=SubscriptionState.ACTIVE))
    last_processed = Column(DateTime, default=datetime.datetime.utcnow())
    account = Column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    lifetime = Column(DateTime)
    comments = Column(String(4000))
    retroactive = Column(Boolean(name='SUBSCRIPTIONS_RETROACTIVE_CHK'), default=False)
    expired_at = Column(DateTime)
    _table_args = (PrimaryKeyConstraint('id', name='SUBSCRIPTIONS_PK'),
                   UniqueConstraint('name', 'account', name='SUBSCRIPTIONS_NAME_ACCOUNT_UQ'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='SUBSCRIPTIONS_ACCOUNT_FK'),
                   CheckConstraint('RETROACTIVE IS NOT NULL', name='SUBSCRIPTIONS_RETROACTIVE_NN'),
                   CheckConstraint('ACCOUNT IS NOT NULL', name='SUBSCRIPTIONS_ACCOUNT_NN'))


class Token(BASE, ModelBase):
    """Represents the authentication tokens and their lifetime"""
    __tablename__ = 'tokens'
    token = Column(String(3072))  # account-identity-appid-uuid -> max length: (+ 30 1 255 1 32 1 32)
    account = Column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    refresh_token = Column(String(315), default=None)
    refresh = Column(Boolean(name='TOKENS_REFRESH_CHK'), default=False)
    refresh_start = Column(DateTime, default=None)
    refresh_expired_at = Column(DateTime, default=None)
    refresh_lifetime = Column(Integer())
    oidc_scope = Column(String(2048), default=None)  # scopes define the specific actions applications can be allowed to do on a user's behalf
    identity = Column(String(2048))
    audience = Column(String(315), default=None)
    expired_at = Column(DateTime, default=lambda: datetime.datetime.utcnow() + datetime.timedelta(seconds=3600))  # one hour lifetime by default
    ip = Column(String(39), nullable=True)
    _table_args = (PrimaryKeyConstraint('token', name='TOKENS_TOKEN_PK'),  # not supported for primary key constraint mysql_length=255
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='TOKENS_ACCOUNT_FK'),
                   CheckConstraint('EXPIRED_AT IS NOT NULL', name='TOKENS_EXPIRED_AT_NN'),
                   Index('TOKENS_ACCOUNT_EXPIRED_AT_IDX', 'account', 'expired_at'))


class OAuthRequest(BASE, ModelBase):
    """Represents the authentication session parameters of OAuth 2.0 requests"""
    __tablename__ = 'oauth_requests'
    account = Column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    state = Column(String(50))
    nonce = Column(String(50))
    access_msg = Column(String(2048))
    redirect_msg = Column(String(2048))
    refresh_lifetime = Column(Integer())
    ip = Column(String(39), nullable=True)
    expired_at = Column(DateTime, default=lambda: datetime.datetime.utcnow() + datetime.timedelta(seconds=600))  # 10 min lifetime by default
    _table_args = (PrimaryKeyConstraint('state', name='OAUTH_REQUESTS_STATE_PK'),
                   CheckConstraint('EXPIRED_AT IS NOT NULL', name='OAUTH_REQUESTS_EXPIRED_AT_NN'),
                   Index('OAUTH_REQUESTS_ACC_EXP_AT_IDX', 'account', 'expired_at'),
                   Index('OAUTH_REQUESTS_ACCESS_MSG_IDX', 'access_msg'))


class Message(BASE, ModelBase):
    """Represents the event messages"""
    __tablename__ = 'messages'
    id = Column(GUID(), default=utils.generate_uuid)
    event_type = Column(String(1024))
    payload = Column(String(4000))
    payload_nolimit = Column(Text)
    services = Column(String(2048))
    _table_args = (PrimaryKeyConstraint('id', name='MESSAGES_ID_PK'),
                   CheckConstraint('EVENT_TYPE IS NOT NULL', name='MESSAGES_EVENT_TYPE_NN'),
                   CheckConstraint('PAYLOAD IS NOT NULL', name='MESSAGES_PAYLOAD_NN'),)


class MessageHistory(BASE, ModelBase):
    """Represents the history of event messages"""
    __tablename__ = 'messages_history'
    id = Column(GUID())
    event_type = Column(String(1024))
    payload = Column(String(4000))
    payload_nolimit = Column(Text)
    services = Column(String(2048))
    __mapper_args__ = {
        'primary_key': [id]  # Fake primary key for SQLA
    }
    _table_args = ()  # PrimaryKeyConstraint('id', name='MESSAGES_HIST_ID_PK'),)  # PK needed for SQLA only


class AlembicVersion(BASE):
    """Table used to pinpoint actual database schema release."""
    __tablename__ = "alembic_version"
    version_num = Column(String(32), primary_key=True, nullable=False)


class Config(BASE, ModelBase, Versioned):
    """Represents the configuration"""
    __tablename__ = 'configs'
    section = Column(String(128))
    opt = Column(String(128))
    value = Column(String(4000))
    _table_args = (PrimaryKeyConstraint('section', 'opt', name='CONFIGS_PK'), )


class Heartbeats(BASE, ModelBase):
    """Represents the status and heartbeat of the running daemons and services"""
    __tablename__ = 'heartbeats'
    executable = Column(String(64))  # SHA-2
    readable = Column(String(4000))
    hostname = Column(String(128))
    pid = Column(Integer, autoincrement=False)
    thread_id = Column(BigInteger, autoincrement=False)
    thread_name = Column(String(64))
    payload = Column(String(3000))
    _table_args = (PrimaryKeyConstraint('executable', 'hostname', 'pid', 'thread_id', name='HEARTBEATS_PK'), )


class NamingConvention(BASE, ModelBase):
    """Represents naming conventions for name within a scope"""
    __tablename__ = 'naming_conventions'
    scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    regexp = Column(String(255))
    convention_type = Column(KeyType.db_type(name='CVT_TYPE_CHK'))
    _table_args = (PrimaryKeyConstraint('scope', name='NAMING_CONVENTIONS_PK'),
                   ForeignKeyConstraint(['scope'], ['scopes.scope'], name='NAMING_CONVENTIONS_SCOPE_FK'))


class TemporaryDataIdentifier(BASE, ModelBase):
    """Represents a temporary DID (pre-merged files, etc.)"""
    __tablename__ = 'tmp_dids'
    scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name = Column(String(get_schema_value('NAME_LENGTH')))
    rse_id = Column(GUID())
    path = Column(String(1024))
    bytes = Column(BigInteger)
    md5 = Column(String(32))
    adler32 = Column(String(8))
    expired_at = Column(DateTime)
    guid = Column(GUID())
    events = Column(BigInteger)
    task_id = Column(Integer())
    panda_id = Column(Integer())
    parent_scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    parent_name = Column(String(get_schema_value('NAME_LENGTH')))
    offset = Column(BigInteger)
    _table_args = (PrimaryKeyConstraint('scope', 'name', name='TMP_DIDS_PK'),
                   Index('TMP_DIDS_EXPIRED_AT_IDX', 'expired_at'))


class LifetimeExceptions(BASE, ModelBase):
    """Represents the exceptions to the lifetime model"""
    __tablename__ = 'lifetime_except'
    id = Column(GUID(), default=utils.generate_uuid)
    scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name = Column(String(get_schema_value('NAME_LENGTH')))
    did_type = Column(DIDType.db_type(name='LIFETIME_EXCEPT_TYPE_CHK'))
    account = Column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    pattern = Column(String(255))
    comments = Column(String(4000))
    state = Column(LifetimeExceptionsState.db_type(name='LIFETIME_EXCEPT_STATE_CHK'))
    expires_at = Column(DateTime)
    _table_args = (PrimaryKeyConstraint('id', 'scope', 'name', 'did_type', 'account', name='LIFETIME_EXCEPT_PK'),
                   CheckConstraint('SCOPE IS NOT NULL', name='LIFETIME_EXCEPT_SCOPE_NN'),
                   CheckConstraint('NAME IS NOT NULL', name='LIFETIME_EXCEPT_NAME_NN'),
                   CheckConstraint('DID_TYPE IS NOT NULL', name='LIFETIME_EXCEPT_DID_TYPE_NN'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='LIFETIME_EXCEPT_ACCOUNT_FK'))


class VO(BASE, ModelBase):
    """Represents the VOS in a MultiVO setup"""
    __tablename__ = 'vos'
    vo = Column(String(3))
    description = Column(String(255))
    email = Column(String(255))
    _table_args = (PrimaryKeyConstraint('vo', name='VOS_PK'), )


class DidsFollowed(BASE, ModelBase):
    """Represents the datasets followed by an user"""
    __tablename__ = 'dids_followed'
    scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name = Column(String(get_schema_value('NAME_LENGTH')))
    account = Column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    did_type = Column(DIDType.db_type(name='DIDS_FOLLOWED_TYPE_CHK'))
    _table_args = (PrimaryKeyConstraint('scope', 'name', 'account', name='DIDS_FOLLOWED_PK'),
                   CheckConstraint('SCOPE IS NOT NULL', name='DIDS_FOLLOWED_SCOPE_NN'),
                   CheckConstraint('NAME IS NOT NULL', name='DIDS_FOLLOWED_NAME_NN'),
                   CheckConstraint('ACCOUNT IS NOT NULL', name='DIDS_FOLLOWED_ACCOUNT_NN'),
                   CheckConstraint('DID_TYPE IS NOT NULL', name='DIDS_FOLLOWED_DID_TYPE_NN'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='DIDS_FOLLOWED_ACCOUNT_FK'),
                   ForeignKeyConstraint(['scope', 'name'], ['dids.scope', 'dids.name'], name='DIDS_FOLLOWED_SCOPE_NAME_FK'))


class FollowEvents(BASE, ModelBase):
    """Represents the events affecting the datasets which are followed"""
    __tablename__ = 'dids_followed_events'
    scope = Column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name = Column(String(get_schema_value('NAME_LENGTH')))
    account = Column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    did_type = Column(DIDType.db_type(name='DIDS_FOLLOWED_EVENTS_TYPE_CHK'))
    event_type = Column(String(1024))
    payload = Column(Text)
    _table_args = (PrimaryKeyConstraint('scope', 'name', 'account', name='DIDS_FOLLOWED_EVENTS_PK'),
                   CheckConstraint('SCOPE IS NOT NULL', name='DIDS_FOLLOWED_EVENTS_SCOPE_NN'),
                   CheckConstraint('NAME IS NOT NULL', name='DIDS_FOLLOWED_EVENTS_NAME_NN'),
                   CheckConstraint('ACCOUNT IS NOT NULL', name='DIDS_FOLLOWED_EVENTS_ACC_NN'),
                   CheckConstraint('DID_TYPE IS NOT NULL', name='DIDS_FOLLOWED_EVENTS_TYPE_NN'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='DIDS_FOLLOWED_EVENTS_ACC_FK'),
                   Index('DIDS_FOLLOWED_EVENTS_ACC_IDX', 'account'))


def register_models(engine):
    """
    Creates database tables for all models with the given engine
    """

    models = (Account,
              AccountAttrAssociation,
              AccountLimit,
              AccountGlobalLimit,
              AccountUsage,
              AlembicVersion,
              BadReplicas,
              CollectionReplica,
              Config,
              ConstituentAssociation,
              ConstituentAssociationHistory,
              DataIdentifierAssociation,
              DataIdentifierAssociationHistory,
              DIDKey,
              DIDKeyValueAssociation,
              DataIdentifier,
              DidMeta,
              DeletedDataIdentifier,
              DidsFollowed,
              FollowEvents,
              Heartbeats,
              Identity,
              IdentityAccountAssociation,
              LifetimeExceptions,
              Message,
              MessageHistory,
              NamingConvention,
              OAuthRequest,
              QuarantinedReplica,
              RSE,
              RSEAttrAssociation,
              RSEFileAssociation,
              RSEFileAssociationHistory,
              RSELimit,
              RSEProtocols,
              RSEQoSAssociation,
              RSEUsage,
              ReplicaLock,
              ReplicationRule,
              ReplicationRule,
              ReplicationRuleHistory,
              ReplicationRuleHistoryRecent,
              Request,
              Scope,
              Source,
              Subscription,
              TemporaryDataIdentifier,
              Token,
              UpdatedAccountCounter,
              UpdatedDID,
              UpdatedRSECounter,
              UpdatedCollectionReplica,
              VO)

    for model in models:
        model.metadata.create_all(engine)   # pylint: disable=maybe-no-member


def unregister_models(engine):
    """
    Drops database tables for all models with the given engine
    """
    models = (Account,
              AccountAttrAssociation,
              AccountLimit,
              AccountGlobalLimit,
              AccountUsage,
              AlembicVersion,
              BadReplicas,
              CollectionReplica,
              Config,
              ConstituentAssociation,
              ConstituentAssociationHistory,
              DataIdentifierAssociation,
              DataIdentifierAssociationHistory,
              DIDKey,
              DIDKeyValueAssociation,
              DidMeta,
              DataIdentifier,
              DeletedDataIdentifier,
              DidsFollowed,
              FollowEvents,
              Heartbeats,
              Identity,
              IdentityAccountAssociation,
              LifetimeExceptions,
              Message,
              MessageHistory,
              NamingConvention,
              OAuthRequest,
              QuarantinedReplica,
              RSE,
              RSEAttrAssociation,
              RSEFileAssociation,
              RSEFileAssociationHistory,
              RSELimit,
              RSEProtocols,
              RSEQoSAssociation,
              RSEUsage,
              ReplicaLock,
              ReplicationRule,
              ReplicationRule,
              ReplicationRuleHistory,
              ReplicationRuleHistoryRecent,
              Request,
              Scope,
              Source,
              Subscription,
              Token,
              TemporaryDataIdentifier,
              UpdatedAccountCounter,
              UpdatedDID,
              UpdatedRSECounter,
              UpdatedCollectionReplica,
              VO)

    for model in models:
        model.metadata.drop_all(engine)   # pylint: disable=maybe-no-member
