# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

import uuid
from datetime import datetime, timedelta
from typing import Any, Optional, Union

from sqlalchemy import BigInteger, Boolean, DateTime, Enum, Float, Integer, SmallInteger, String, Text, event, UniqueConstraint
from sqlalchemy.engine import Engine
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import mapped_column, object_mapper, relationship, Mapped
from sqlalchemy.schema import Index, ForeignKeyConstraint, PrimaryKeyConstraint, CheckConstraint, Table
from sqlalchemy.sql import Delete
from sqlalchemy.types import LargeBinary

from rucio.common import utils
from rucio.common.schema import get_schema_value
from rucio.common.types import InternalAccount, InternalScope
from rucio.db.sqla.constants import (AccountStatus, AccountType, DIDAvailability, DIDType, DIDReEvaluation,
                                     KeyType, IdentityType, LockState, RuleGrouping, BadFilesStatus,
                                     RuleState, ReplicaState, RequestState, RequestType, RSEType,
                                     ScopeStatus, SubscriptionState, RuleNotification, LifetimeExceptionsState,
                                     BadPFNStatus, TransferLimitDirection)
from rucio.db.sqla.session import BASE
from rucio.db.sqla.types import GUID, BooleanString, JSON
from rucio.db.sqla.types import InternalAccountString
from rucio.db.sqla.types import InternalScopeString


# SQLAlchemy defines the corresponding code behind TYPE_CHECKING
# https://github.com/sqlalchemy/sqlalchemy/blob/d9acd6223299c118464d30abfa483e26a536239d/lib/sqlalchemy/orm/base.py#L814
# And pylint/astroid don't have an option to evaluate this code
# https://github.com/pylint-dev/astroid/issues/1332
# So we get this error all over the place: `E1136: Value 'Mapped' is unsubscriptable (unsubscriptable-object)`
#
# pylint: disable=E1136


@compiles(Boolean, "oracle")
def compile_binary_oracle(type_, compiler, **kw):
    return "NUMBER(1)"


@event.listens_for(Table, "before_create")
def _mysql_rename_type(target, connection, **kw):
    if connection.dialect.name == 'mysql' and target.name == 'quarantined_replicas':
        target.columns.path.type = String(255)


@event.listens_for(Table, "before_create")
def _psql_rename_type(target, connection, **kw):
    if connection.dialect.name == 'postgresql' and target.name == 'account_map':
        target.columns.identity_type.type.name = 'IDENTITIES_TYPE_CHK'


@event.listens_for(Table, "before_create")
def _oracle_json_constraint(target, connection, **kw):
    if connection.dialect.name == 'oracle':
        try:
            oracle_version = int(connection.connection.version.split('.')[0])
        except Exception:
            return
        if oracle_version >= 12:
            if target.name == 'did_meta':
                target.append_constraint(CheckConstraint('META IS JSON', 'ORACLE_META_JSON_CHK'))
            if target.name == 'virtual_placements':
                target.append_constraint(CheckConstraint('PLACEMENTS IS JSON', 'ORACLE_PLACEMENTS_JSON_CHK'))


@event.listens_for(Engine, "before_execute", retval=True)
def _add_hint(conn, element, multiparams, params, execution_options):
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
    elif const.name == 'QUARANTINED_REPLICAS_HISTORY_CREATED_NN' and table.name.upper() == 'QUARANTINED_REPLICAS_HISTORY':
        const.name = "QURD_REPLICAS_HIST_CREATED_NN"
    elif const.name == 'QUARANTINED_REPLICAS_HISTORY_UPDATED_NN' and table.name.upper() == 'QUARANTINED_REPLICAS_HISTORY':
        const.name = "QURD_REPLICAS_HIST_UPDATED_NN"
    elif const.name == 'ARCHIVE_CONTENTS_HISTORY_CREATED_NN' and table.name.upper() == 'ARCHIVE_CONTENTS_HISTORY':
        const.name = "ARCH_CNTS_HIST_CREATED_NN"
    elif const.name == 'ARCHIVE_CONTENTS_HISTORY_UPDATED_NN' and table.name.upper() == 'ARCHIVE_CONTENTS_HISTORY':
        const.name = "ARCH_CNTS_HIST_UPDATED_NN"
    elif const.name == 'ACCOUNT_USAGE_HISTORY_CREATED_NN' and table.name.upper() == 'ACCOUNT_USAGE_HISTORY':
        const.name = "ACCOUNT_USAGE_HIST_CREATED_NN"
    elif const.name == 'ACCOUNT_USAGE_HISTORY_UPDATED_NN' and table.name.upper() == 'ACCOUNT_USAGE_HISTORY':
        const.name = "ACCOUNT_USAGE_HIST_UPDATED_NN"
    elif const.name == 'SUBSCRIPTIONS_HISTORY_CREATED_NN' and table.name.upper() == 'SUBSCRIPTIONS_HISTORY':
        const.name = "SUBSCRIPTIONS_HIST_CREATED_NN"
    elif const.name == 'SUBSCRIPTIONS_HISTORY_UPDATED_NN' and table.name.upper() == 'SUBSCRIPTIONS_HISTORY':
        const.name = "SUBSCRIPTIONS_HIST_UPDATED_NN"

    if const.name is None:
        const.name = table.name.upper() + '_' + str(uuid.uuid4())[:6] + '_CHK'

    if const.name == 'REQUESTS_TYPE_CHK' and table.name.upper() == 'REQUESTS_HISTORY':
        const.name = "REQUESTS_HISTORY_TYPE_CHK"
    elif const.name == 'REQUESTS_DIDTYPE_CHK' and table.name.upper() == 'REQUESTS_HISTORY':
        const.name = "REQUESTS_HISTORY_DIDTYPE_CHK"
    elif const.name == 'REQUESTS_DIDTYPE_CHK' and table.name.upper() == 'REQUESTS_HISTORY':
        const.name = "REQUESTS_HISTORY_DIDTYPE_CHK"
    elif const.name == 'REQUESTS_STATE_CHK' and table.name.upper() == 'REQUESTS_HISTORY':
        const.name = "REQUESTS_HISTORY_STATE_CHK"


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
        return mapped_column("created_at", DateTime, default=datetime.utcnow)

    @declared_attr
    def updated_at(cls):  # pylint: disable=no-self-argument
        return mapped_column("updated_at", DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def save(self, flush=True, session=None):
        """Save this object"""
        # Sessions created with autoflush=True be default since sqlAlchemy 1.4.
        # So explicatly calling session.flush is not necessary.
        # However, when autogenerated primary keys involved, calling
        # session.flush to get the id from DB.
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
        for k, v in values.items():
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
        dictionary = self.__dict__.copy()
        dictionary.pop('_sa_instance_state')
        return dictionary

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
                                  {'mysql_engine': 'InnoDB'})

    @declared_attr
    def deleted(cls):  # pylint: disable=no-self-argument
        return mapped_column("deleted", Boolean, default=False)

    @declared_attr
    def deleted_at(cls):  # pylint: disable=no-self-argument
        return mapped_column("deleted_at", DateTime)

    def delete(self, flush=True, session=None):
        """Delete this object"""
        self.deleted = True
        self.deleted_at = datetime.utcnow()
        self.save(session=session)


class Account(BASE, ModelBase):
    """Represents an account"""
    __tablename__ = 'accounts'
    account: Mapped[InternalAccount] = mapped_column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    account_type: Mapped[AccountType] = mapped_column(Enum(AccountType, name='ACCOUNTS_TYPE_CHK',
                                                           create_constraint=True,
                                                           values_callable=lambda obj: [e.value for e in obj]))
    status: Mapped[AccountStatus] = mapped_column(Enum(AccountStatus, name='ACCOUNTS_STATUS_CHK',
                                                       create_constraint=True,
                                                       values_callable=lambda obj: [e.value for e in obj]),
                                                  default=AccountStatus.ACTIVE, )
    email: Mapped[Optional[str]] = mapped_column(String(255))
    suspended_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    _table_args = (PrimaryKeyConstraint('account', name='ACCOUNTS_PK'),
                   CheckConstraint('ACCOUNT_TYPE IS NOT NULL', name='ACCOUNTS_TYPE_NN'),
                   CheckConstraint('STATUS IS NOT NULL', name='ACCOUNTS_STATUS_NN'))


class AccountAttrAssociation(BASE, ModelBase):
    """Represents an account"""
    __tablename__ = 'account_attr_map'
    account: Mapped[InternalAccount] = mapped_column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    key: Mapped[str] = mapped_column(String(255))
    value: Mapped[Optional[Union[bool, str]]] = mapped_column(BooleanString(255))
    _table_args = (PrimaryKeyConstraint('account', 'key', name='ACCOUNT_ATTR_MAP_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='ACCOUNT_ATTR_MAP_ACCOUNT_FK'),
                   Index('ACCOUNT_ATTR_MAP_KEY_VALUE_IDX', 'key', 'value'))


class Identity(BASE, SoftModelBase):
    """Represents an identity"""
    __tablename__ = 'identities'
    identity: Mapped[str] = mapped_column(String(2048))
    identity_type: Mapped[IdentityType] = mapped_column(Enum(IdentityType, name='IDENTITIES_TYPE_CHK',
                                                             create_constraint=True,
                                                             values_callable=lambda obj: [e.value for e in obj]))
    username: Mapped[Optional[str]] = mapped_column(String(255))
    password: Mapped[Optional[str]] = mapped_column(String(255))
    salt = mapped_column(LargeBinary(255))
    email: Mapped[str] = mapped_column(String(255))
    _table_args = (PrimaryKeyConstraint('identity', 'identity_type', name='IDENTITIES_PK'),
                   CheckConstraint('IDENTITY_TYPE IS NOT NULL', name='IDENTITIES_TYPE_NN'),
                   CheckConstraint('EMAIL IS NOT NULL', name='IDENTITIES_EMAIL_NN'))


class IdentityAccountAssociation(BASE, ModelBase):
    """Represents a map account-identity"""
    __tablename__ = 'account_map'
    identity: Mapped[str] = mapped_column(String(2048))
    identity_type: Mapped[IdentityType] = mapped_column(Enum(IdentityType, name='ACCOUNT_MAP_ID_TYPE_CHK',
                                                             create_constraint=True,
                                                             values_callable=lambda obj: [e.value for e in obj]))
    account: Mapped[InternalAccount] = mapped_column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    is_default: Mapped[bool] = mapped_column(Boolean(name='ACCOUNT_MAP_DEFAULT_CHK', create_constraint=True),
                                             default=False)
    _table_args = (PrimaryKeyConstraint('identity', 'identity_type', 'account', name='ACCOUNT_MAP_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='ACCOUNT_MAP_ACCOUNT_FK'),
                   ForeignKeyConstraint(['identity', 'identity_type'], ['identities.identity', 'identities.identity_type'], name='ACCOUNT_MAP_ID_TYPE_FK'),
                   CheckConstraint('is_default IS NOT NULL', name='ACCOUNT_MAP_IS_DEFAULT_NN'),
                   CheckConstraint('IDENTITY_TYPE IS NOT NULL', name='ACCOUNT_MAP_ID_TYPE_NN'))


class Scope(BASE, ModelBase):
    """Represents a scope"""
    __tablename__ = 'scopes'
    scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    account: Mapped[InternalAccount] = mapped_column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    is_default: Mapped[bool] = mapped_column(Boolean(name='SCOPES_DEFAULT_CHK', create_constraint=True),
                                             default=False)
    status: Mapped[ScopeStatus] = mapped_column(Enum(ScopeStatus, name='SCOPE_STATUS_CHK',
                                                     create_constraint=True,
                                                     values_callable=lambda obj: [e.value for e in obj]),
                                                default=ScopeStatus.OPEN)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    _table_args = (PrimaryKeyConstraint('scope', name='SCOPES_SCOPE_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='SCOPES_ACCOUNT_FK'),
                   CheckConstraint('is_default IS NOT NULL', name='SCOPES_IS_DEFAULT_NN'),
                   CheckConstraint('STATUS IS NOT NULL', name='SCOPES_STATUS_NN'),
                   CheckConstraint('ACCOUNT IS NOT NULL', name='SCOPES_ACCOUNT_NN'))


class DataIdentifier(BASE, ModelBase):
    """Represents a dataset"""
    __tablename__ = 'dids'
    scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name: Mapped[str] = mapped_column(String(get_schema_value('NAME_LENGTH')))
    account: Mapped[InternalAccount] = mapped_column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    did_type: Mapped[DIDType] = mapped_column(Enum(DIDType, name='DIDS_TYPE_CHK',
                                                   create_constraint=True,
                                                   values_callable=lambda obj: [e.value for e in obj]))
    is_open: Mapped[Optional[bool]] = mapped_column(Boolean(name='DIDS_IS_OPEN_CHK', create_constraint=True))
    monotonic: Mapped[bool] = mapped_column(Boolean(name='DIDS_MONOTONIC_CHK', create_constraint=True),
                                            server_default='0')
    hidden: Mapped[bool] = mapped_column(Boolean(name='DIDS_HIDDEN_CHK', create_constraint=True),
                                         server_default='0')
    obsolete: Mapped[bool] = mapped_column(Boolean(name='DIDS_OBSOLETE_CHK', create_constraint=True),
                                           server_default='0')
    complete: Mapped[Optional[bool]] = mapped_column(Boolean(name='DIDS_COMPLETE_CHK', create_constraint=True),
                                                     server_default=None)
    is_new: Mapped[Optional[bool]] = mapped_column(Boolean(name='DIDS_IS_NEW_CHK', create_constraint=True),
                                                   server_default='1')
    availability: Mapped[DIDAvailability] = mapped_column(Enum(DIDAvailability, name='DIDS_AVAILABILITY_CHK',
                                                               create_constraint=True,
                                                               values_callable=lambda obj: [e.value for e in obj]),
                                                          default=DIDAvailability.AVAILABLE)
    suppressed: Mapped[bool] = mapped_column(Boolean(name='FILES_SUPP_CHK', create_constraint=True),
                                             server_default='0')
    bytes: Mapped[Optional[int]] = mapped_column(BigInteger)
    length: Mapped[Optional[int]] = mapped_column(BigInteger)
    md5: Mapped[Optional[str]] = mapped_column(String(32))
    adler32: Mapped[Optional[str]] = mapped_column(String(8))
    expired_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    purge_replicas: Mapped[bool] = mapped_column(Boolean(name='DIDS_PURGE_RPLCS_CHK', create_constraint=True),
                                                 server_default='1')
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    # hardcoded meta-data to populate the db
    events: Mapped[Optional[int]] = mapped_column(BigInteger)
    guid: Mapped[Optional[uuid.UUID]] = mapped_column(GUID())
    project: Mapped[Optional[str]] = mapped_column(String(50))
    datatype: Mapped[Optional[str]] = mapped_column(String(50))
    run_number: Mapped[Optional[int]] = mapped_column(Integer)
    stream_name: Mapped[Optional[str]] = mapped_column(String(70))
    prod_step: Mapped[Optional[str]] = mapped_column(String(50))
    version: Mapped[Optional[str]] = mapped_column(String(50))
    campaign: Mapped[Optional[str]] = mapped_column(String(50))
    task_id: Mapped[Optional[int]] = mapped_column(Integer())
    panda_id: Mapped[Optional[int]] = mapped_column(Integer())
    lumiblocknr: Mapped[Optional[int]] = mapped_column(Integer())
    provenance: Mapped[Optional[str]] = mapped_column(String(2))
    phys_group: Mapped[Optional[str]] = mapped_column(String(25))
    transient: Mapped[bool] = mapped_column(Boolean(name='DID_TRANSIENT_CHK', create_constraint=True),
                                            server_default='0')
    accessed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    eol_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    is_archive: Mapped[Optional[bool]] = mapped_column(Boolean(name='DIDS_ARCHIVE_CHK', create_constraint=True))
    constituent: Mapped[Optional[bool]] = mapped_column(Boolean(name='DIDS_CONSTITUENT_CHK', create_constraint=True))
    access_cnt: Mapped[Optional[int]] = mapped_column(Integer())
    _table_args = (PrimaryKeyConstraint('scope', 'name', name='DIDS_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], ondelete='CASCADE', name='DIDS_ACCOUNT_FK'),
                   ForeignKeyConstraint(['scope'], ['scopes.scope'], name='DIDS_SCOPE_FK'),
                   CheckConstraint('MONOTONIC IS NOT NULL', name='DIDS_MONOTONIC_NN'),
                   CheckConstraint('OBSOLETE IS NOT NULL', name='DIDS_OBSOLETE_NN'),
                   CheckConstraint('SUPPRESSED IS NOT NULL', name='DIDS_SUPP_NN'),
                   CheckConstraint('ACCOUNT IS NOT NULL', name='DIDS_ACCOUNT_NN'),
                   CheckConstraint('PURGE_REPLICAS IS NOT NULL', name='DIDS_PURGE_REPLICAS_NN'),
                   Index('DIDS_IS_NEW_IDX', 'is_new'),
                   Index('DIDS_EXPIRED_AT_IDX', 'expired_at'))


class VirtualPlacements(BASE, ModelBase):
    """Represents virtual placements"""
    __tablename__ = 'virtual_placements'
    scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name: Mapped[str] = mapped_column(String(get_schema_value('NAME_LENGTH')))
    placements = mapped_column(JSON())
    _table_args = (PrimaryKeyConstraint('scope', 'name', name='VP_PK'),
                   ForeignKeyConstraint(['scope', 'name'], ['dids.scope', 'dids.name'], name='VP_FK')
                   )


class DidMeta(BASE, ModelBase):
    __tablename__ = 'did_meta'
    scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name: Mapped[str] = mapped_column(String(get_schema_value('NAME_LENGTH')))
    meta: Mapped[Optional[Union[str, dict[str, Any]]]] = mapped_column(JSON())
    did_type: Mapped[Optional[DIDType]] = mapped_column(Enum(DIDType, name='DID_META_DID_TYPE_CHK',
                                                             create_constraint=True,
                                                             values_callable=lambda obj: [e.value for e in obj]))
    _table_args = (PrimaryKeyConstraint('scope', 'name', name='DID_META_PK'),
                   ForeignKeyConstraint(['scope', 'name'], ['dids.scope', 'dids.name'], name='DID_META_FK'),
                   Index('DID_META_DID_TYPE_IDX', 'did_type'))


class DeletedDataIdentifier(BASE, ModelBase):
    """Represents a dataset"""
    __tablename__ = 'deleted_dids'
    scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name: Mapped[str] = mapped_column(String(get_schema_value('NAME_LENGTH')))
    account: Mapped[InternalAccount] = mapped_column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    did_type: Mapped[DIDType] = mapped_column(Enum(DIDType, name='DEL_DIDS_TYPE_CHK',
                                                   create_constraint=True,
                                                   values_callable=lambda obj: [e.value for e in obj]))
    is_open: Mapped[Optional[bool]] = mapped_column(Boolean(name='DEL_DIDS_IS_OPEN_CHK', create_constraint=True))
    monotonic: Mapped[bool] = mapped_column(Boolean(name='DEL_DIDS_MONO_CHK', create_constraint=True),
                                            server_default='0')
    hidden: Mapped[bool] = mapped_column(Boolean(name='DEL_DIDS_HIDDEN_CHK', create_constraint=True),
                                         server_default='0')
    obsolete: Mapped[bool] = mapped_column(Boolean(name='DEL_DIDS_OBSOLETE_CHK', create_constraint=True),
                                           server_default='0')
    complete: Mapped[Optional[bool]] = mapped_column(Boolean(name='DEL_DIDS_COMPLETE_CHK', create_constraint=True))
    is_new: Mapped[Optional[bool]] = mapped_column(Boolean(name='DEL_DIDS_IS_NEW_CHK', create_constraint=True),
                                                   server_default='1')
    availability: Mapped[DIDAvailability] = mapped_column(Enum(DIDAvailability, name='DEL_DIDS_AVAIL_CHK',
                                                               create_constraint=True,
                                                               values_callable=lambda obj: [e.value for e in obj]),
                                                          default=DIDAvailability.AVAILABLE)
    suppressed: Mapped[bool] = mapped_column(Boolean(name='DEL_FILES_SUPP_CHK', create_constraint=True),
                                             server_default='0')
    bytes: Mapped[Optional[int]] = mapped_column(BigInteger)
    length: Mapped[Optional[int]] = mapped_column(BigInteger)
    md5: Mapped[Optional[str]] = mapped_column(String(32))
    adler32: Mapped[Optional[str]] = mapped_column(String(8))
    expired_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    events: Mapped[Optional[int]] = mapped_column(BigInteger)
    guid: Mapped[Optional[uuid.UUID]] = mapped_column(GUID())
    project: Mapped[Optional[str]] = mapped_column(String(50))
    datatype: Mapped[Optional[str]] = mapped_column(String(50))
    run_number: Mapped[Optional[int]] = mapped_column(Integer)
    stream_name: Mapped[Optional[str]] = mapped_column(String(70))
    prod_step: Mapped[Optional[str]] = mapped_column(String(50))
    version: Mapped[Optional[str]] = mapped_column(String(50))
    campaign: Mapped[Optional[str]] = mapped_column(String(50))
    task_id: Mapped[Optional[int]] = mapped_column(Integer())
    panda_id: Mapped[Optional[int]] = mapped_column(Integer())
    lumiblocknr: Mapped[Optional[int]] = mapped_column(Integer())
    provenance: Mapped[Optional[str]] = mapped_column(String(2))
    phys_group: Mapped[Optional[str]] = mapped_column(String(25))
    transient: Mapped[bool] = mapped_column(Boolean(name='DEL_DID_TRANSIENT_CHK', create_constraint=True),
                                            server_default='0')
    purge_replicas: Mapped[Optional[bool]] = mapped_column(Boolean(name='DELETED_DIDS_PURGE_RPLCS_CHK', create_constraint=True))
    accessed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    eol_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    is_archive: Mapped[Optional[bool]] = mapped_column(Boolean(name='DEL_DIDS_ARCH_CHK', create_constraint=True))
    constituent: Mapped[Optional[bool]] = mapped_column(Boolean(name='DEL_DIDS_CONST_CHK', create_constraint=True))
    access_cnt: Mapped[Optional[int]] = mapped_column(Integer())
    _table_args = (PrimaryKeyConstraint('scope', 'name', name='DELETED_DIDS_PK'), )


class UpdatedDID(BASE, ModelBase):
    """Represents the recently updated dids"""
    __tablename__ = 'updated_dids'
    id: Mapped[uuid.UUID] = mapped_column(GUID(), default=utils.generate_uuid)
    scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name: Mapped[str] = mapped_column(String(get_schema_value('NAME_LENGTH')))
    rule_evaluation_action: Mapped[DIDReEvaluation] = mapped_column(Enum(DIDReEvaluation, name='UPDATED_DIDS_RULE_EVAL_ACT_CHK',
                                                                         create_constraint=True,
                                                                         values_callable=lambda obj: [e.value for e in obj]))
    _table_args = (PrimaryKeyConstraint('id', name='UPDATED_DIDS_PK'),
                   CheckConstraint('SCOPE IS NOT NULL', name='UPDATED_DIDS_SCOPE_NN'),
                   CheckConstraint('NAME IS NOT NULL', name='UPDATED_DIDS_NAME_NN'),
                   Index('UPDATED_DIDS_SCOPERULENAME_IDX', 'scope', 'rule_evaluation_action', 'name'))


class BadReplicas(BASE, ModelBase):
    """Represents the suspicious or bad replicas"""
    __tablename__ = 'bad_replicas'
    scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name: Mapped[str] = mapped_column(String(get_schema_value('NAME_LENGTH')))
    rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    reason: Mapped[Optional[str]] = mapped_column(String(255))
    state: Mapped[BadFilesStatus] = mapped_column(Enum(BadFilesStatus, name='BAD_REPLICAS_STATE_CHK',
                                                       create_constraint=True,
                                                       values_callable=lambda obj: [e.value for e in obj]),
                                                  default=BadFilesStatus.SUSPICIOUS)
    account: Mapped[InternalAccount] = mapped_column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    bytes: Mapped[Optional[int]] = mapped_column(BigInteger)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    _table_args = (PrimaryKeyConstraint('scope', 'name', 'rse_id', 'state', 'created_at', name='BAD_REPLICAS_STATE_PK'),
                   CheckConstraint('SCOPE IS NOT NULL', name='BAD_REPLICAS_SCOPE_NN'),
                   CheckConstraint('NAME IS NOT NULL', name='BAD_REPLICAS_NAME_NN'),
                   CheckConstraint('RSE_ID IS NOT NULL', name='BAD_REPLICAS_RSE_ID_NN'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='BAD_REPLICAS_ACCOUNT_FK'),
                   Index('BAD_REPLICAS_STATE_IDX', 'rse_id', 'state'),
                   Index('BAD_REPLICAS_EXPIRES_AT_IDX', 'expires_at'),
                   Index('BAD_REPLICAS_ACCOUNT_IDX', 'account'))


class BadPFNs(BASE, ModelBase):
    """Represents bad, suspicious or temporary unavailable PFNs which have to be processed and added to BadReplicas Table"""
    __tablename__ = 'bad_pfns'
    path: Mapped[str] = mapped_column(String(2048))  # PREFIX + PFN
    state: Mapped[BadPFNStatus] = mapped_column(Enum(BadPFNStatus, name='BAD_PFNS_STATE_CHK',
                                                     create_constraint=True,
                                                     values_callable=lambda obj: [e.value for e in obj]),
                                                default=BadPFNStatus.SUSPICIOUS)
    reason: Mapped[Optional[str]] = mapped_column(String(255))
    account: Mapped[InternalAccount] = mapped_column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    _table_args = (PrimaryKeyConstraint('path', 'state', name='BAD_PFNS_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='BAD_PFNS_ACCOUNT_FK'))


class QuarantinedReplica(BASE, ModelBase):
    """Represents the quarantined replicas"""
    __tablename__ = 'quarantined_replicas'
    rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    path: Mapped[str] = mapped_column(String(1024))
    bytes: Mapped[Optional[int]] = mapped_column(BigInteger)
    md5: Mapped[Optional[str]] = mapped_column(String(32))
    adler32: Mapped[Optional[str]] = mapped_column(String(8))
    scope: Mapped[Optional[InternalScope]] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name: Mapped[Optional[str]] = mapped_column(String(get_schema_value('NAME_LENGTH')))
    _table_args = (PrimaryKeyConstraint('rse_id', 'path', name='QURD_REPLICAS_STATE_PK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='QURD_REPLICAS_RSE_ID_FK'),
                   Index('QUARANTINED_REPLICAS_PATH_IDX', 'path', 'rse_id', unique=True))


class QuarantinedReplicaHistory(BASE, ModelBase):
    """Represents the quarantined replicas history"""
    __tablename__ = 'quarantined_replicas_history'
    rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    path: Mapped[str] = mapped_column(String(1024))
    bytes: Mapped[Optional[int]] = mapped_column(BigInteger)
    md5: Mapped[Optional[str]] = mapped_column(String(32))
    adler32: Mapped[Optional[str]] = mapped_column(String(8))
    scope: Mapped[Optional[InternalScope]] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name: Mapped[Optional[str]] = mapped_column(String(get_schema_value('NAME_LENGTH')))
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    __mapper_args__ = {
        'primary_key': [rse_id, path]  # Fake primary key for SQLA
    }
    _table_args = ()


class DIDMetaConventionsKey(BASE, ModelBase):
    """Represents allowed keys of DID Metadata"""
    __tablename__ = 'did_keys'
    key: Mapped[str] = mapped_column(String(255))
    is_enum: Mapped[bool] = mapped_column(Boolean(name='DID_KEYS_IS_ENUM_CHK', create_constraint=True),
                                          server_default='0')
    key_type: Mapped[KeyType] = mapped_column(Enum(KeyType, name='DID_KEYS_TYPE_CHK',
                                                   create_constraint=True,
                                                   values_callable=lambda obj: [e.value for e in obj]))
    value_type: Mapped[Optional[str]] = mapped_column(String(255))
    value_regexp: Mapped[Optional[str]] = mapped_column(String(255))
    _table_args = (PrimaryKeyConstraint('key', name='DID_KEYS_PK'),
                   CheckConstraint('key_type IS NOT NULL', name='DID_KEYS_TYPE_NN'),
                   CheckConstraint('is_enum IS NOT NULL', name='DID_KEYS_IS_ENUM_NN'))


class DIDMetaConventionsConstraints(BASE, ModelBase):
    """Represents a map for constraint values a DID metadata key must follow """
    __tablename__ = 'did_key_map'
    key: Mapped[str] = mapped_column(String(255))
    value: Mapped[str] = mapped_column(String(255))
    _table_args = (PrimaryKeyConstraint('key', 'value', name='DID_KEY_MAP_PK'),
                   ForeignKeyConstraint(['key'], ['did_keys.key'], name='DID_MAP_KEYS_FK'))


class DataIdentifierAssociation(BASE, ModelBase):
    """Represents the map between containers/datasets and files"""
    __tablename__ = 'contents'
    scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))  # dataset scope
    name: Mapped[str] = mapped_column(String(get_schema_value('NAME_LENGTH')))    # dataset name
    child_scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))  # Provenance scope
    child_name: Mapped[str] = mapped_column(String(get_schema_value('NAME_LENGTH')))    # Provenance name
    did_type: Mapped[DIDType] = mapped_column(Enum(DIDType, name='CONTENTS_DID_TYPE_CHK',
                                                   create_constraint=True,
                                                   values_callable=lambda obj: [e.value for e in obj]))
    child_type: Mapped[DIDType] = mapped_column(Enum(DIDType, name='CONTENTS_CHILD_TYPE_CHK',
                                                     create_constraint=True,
                                                     values_callable=lambda obj: [e.value for e in obj]))
    bytes: Mapped[Optional[int]] = mapped_column(BigInteger)
    adler32: Mapped[Optional[str]] = mapped_column(String(8))
    md5: Mapped[Optional[str]] = mapped_column(String(32))
    guid: Mapped[Optional[uuid.UUID]] = mapped_column(GUID())
    events: Mapped[Optional[int]] = mapped_column(BigInteger)
    rule_evaluation: Mapped[Optional[bool]] = mapped_column(Boolean(name='CONTENTS_RULE_EVALUATION_CHK', create_constraint=True))
    _table_args = (PrimaryKeyConstraint('scope', 'name', 'child_scope', 'child_name', name='CONTENTS_PK'),
                   ForeignKeyConstraint(['scope', 'name'], ['dids.scope', 'dids.name'], name='CONTENTS_ID_FK'),
                   ForeignKeyConstraint(['child_scope', 'child_name'], ['dids.scope', 'dids.name'], ondelete="CASCADE", name='CONTENTS_CHILD_ID_FK'),
                   CheckConstraint('DID_TYPE IS NOT NULL', name='CONTENTS_DID_TYPE_NN'),
                   CheckConstraint('CHILD_TYPE IS NOT NULL', name='CONTENTS_CHILD_TYPE_NN'),
                   Index('CONTENTS_CHILD_SCOPE_NAME_IDX', 'child_scope', 'child_name', 'scope', 'name'),
                   Index('CONTENTS_RULE_EVAL_FB_IDX', 'rule_evaluation'))  # Under Oracle this is a FB index


class ConstituentAssociation(BASE, ModelBase):
    """Represents the map between archives and constituents"""
    __tablename__ = 'archive_contents'
    child_scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))    # Constituent file scope
    child_name: Mapped[str] = mapped_column(String(get_schema_value('NAME_LENGTH')))    # Constituent file name
    scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))          # Archive file scope
    name: Mapped[str] = mapped_column(String(get_schema_value('NAME_LENGTH')))          # Archive file name
    bytes: Mapped[Optional[int]] = mapped_column(BigInteger)
    adler32: Mapped[Optional[str]] = mapped_column(String(8))
    md5: Mapped[Optional[str]] = mapped_column(String(32))
    guid: Mapped[Optional[uuid.UUID]] = mapped_column(GUID())
    length: Mapped[Optional[int]] = mapped_column(BigInteger)
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
    """Represents the map history between archives and constituents"""
    __tablename__ = 'archive_contents_history'
    child_scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))    # Constituent file scope
    child_name: Mapped[str] = mapped_column(String(get_schema_value('NAME_LENGTH')))    # Constituent file name
    scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))          # Archive file scope
    name: Mapped[str] = mapped_column(String(get_schema_value('NAME_LENGTH')))  # Archive file name
    bytes: Mapped[Optional[int]] = mapped_column(BigInteger)
    adler32: Mapped[Optional[str]] = mapped_column(String(8))
    md5: Mapped[Optional[str]] = mapped_column(String(32))
    guid: Mapped[Optional[uuid.UUID]] = mapped_column(GUID())
    length: Mapped[Optional[int]] = mapped_column(BigInteger)
    __mapper_args__ = {
        'primary_key': [scope, name, child_scope, child_name]  # Fake primary key for SQLA
    }
    _table_args = (Index('ARCH_CONT_HIST_IDX', 'scope', 'name'), )


class DataIdentifierAssociationHistory(BASE, ModelBase):
    """Represents the map history between containers/datasets and files"""
    __tablename__ = 'contents_history'
    scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))          # dataset scope
    name: Mapped[str] = mapped_column(String(get_schema_value('NAME_LENGTH')))  # dataset name
    child_scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))          # Provenance scope
    child_name: Mapped[str] = mapped_column(String(get_schema_value('NAME_LENGTH')))  # Provenance name
    did_type: Mapped[DIDType] = mapped_column(Enum(DIDType, name='CONTENTS_HIST_DID_TYPE_CHK',
                                                   create_constraint=True,
                                                   values_callable=lambda obj: [e.value for e in obj]))
    child_type: Mapped[DIDType] = mapped_column(Enum(DIDType, name='CONTENTS_HIST_CHILD_TYPE_CHK',
                                                     create_constraint=True,
                                                     values_callable=lambda obj: [e.value for e in obj]))
    bytes: Mapped[Optional[int]] = mapped_column(BigInteger)
    adler32: Mapped[Optional[str]] = mapped_column(String(8))
    md5: Mapped[Optional[str]] = mapped_column(String(32))
    guid: Mapped[Optional[uuid.UUID]] = mapped_column(GUID())
    events: Mapped[Optional[int]] = mapped_column(BigInteger)
    rule_evaluation: Mapped[Optional[bool]] = mapped_column(Boolean(name='CONTENTS_HIST_RULE_EVAL_CHK', create_constraint=True))
    did_created_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    __mapper_args__ = {
        'primary_key': [scope, name, child_scope, child_name]  # Fake primary key for SQLA
    }
    _table_args = (CheckConstraint('DID_TYPE IS NOT NULL', name='CONTENTS_HIST_DID_TYPE_NN'),
                   CheckConstraint('CHILD_TYPE IS NOT NULL', name='CONTENTS_HIST_CHILD_TYPE_NN'),
                   Index('CONTENTS_HISTORY_IDX', 'scope', 'name'))


class RSE(BASE, SoftModelBase):
    """Represents a Rucio Location"""
    __tablename__ = 'rses'
    id: Mapped[uuid.UUID] = mapped_column(GUID(), default=utils.generate_uuid)
    rse: Mapped[str] = mapped_column(String(255))
    vo: Mapped[str] = mapped_column(String(3), nullable=False, server_default='def')
    rse_type: Mapped[RSEType] = mapped_column(Enum(RSEType, name='RSES_TYPE_CHK',
                                                   create_constraint=True,
                                                   values_callable=lambda obj: [e.value for e in obj]),
                                              default=RSEType.DISK)
    deterministic: Mapped[bool] = mapped_column(Boolean(name='RSE_DETERMINISTIC_CHK', create_constraint=True),
                                                default=True)
    volatile: Mapped[bool] = mapped_column(Boolean(name='RSE_VOLATILE_CHK', create_constraint=True),
                                           default=False)
    staging_area: Mapped[bool] = mapped_column(Boolean(name='RSE_STAGING_AREA_CHK', create_constraint=True),
                                               default=False)
    city: Mapped[Optional[str]] = mapped_column(String(255))
    region_code: Mapped[Optional[str]] = mapped_column(String(2))
    country_name: Mapped[Optional[str]] = mapped_column(String(255))
    continent: Mapped[Optional[str]] = mapped_column(String(2))
    time_zone: Mapped[Optional[str]] = mapped_column(String(255))
    ISP: Mapped[Optional[str]] = mapped_column(String(255))
    ASN: Mapped[Optional[str]] = mapped_column(String(255))
    longitude: Mapped[Optional[float]] = mapped_column(Float())
    latitude: Mapped[Optional[float]] = mapped_column(Float())
    availability: Mapped[int] = mapped_column(Integer, server_default='7')  # Deprecated, will be removedx
    availability_read: Mapped[bool] = mapped_column(Boolean, default=True)
    availability_write: Mapped[bool] = mapped_column(Boolean, default=True)
    availability_delete: Mapped[bool] = mapped_column(Boolean, default=True)
    usage = relationship("RSEUsage", order_by="RSEUsage.rse_id", backref="rses")
    qos_class: Mapped[Optional[str]] = mapped_column(String(64))
    _table_args = (PrimaryKeyConstraint('id', name='RSES_PK'),
                   UniqueConstraint('rse', 'vo', name='RSES_RSE_UQ'),
                   CheckConstraint('RSE IS NOT NULL', name='RSES_RSE__NN'),
                   CheckConstraint('RSE_TYPE IS NOT NULL', name='RSES_TYPE_NN'),
                   ForeignKeyConstraint(['vo'], ['vos.vo'], name='RSES_VOS_FK'), )


class RSELimit(BASE, ModelBase):
    """Represents RSE limits"""
    __tablename__ = 'rse_limits'
    rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    name: Mapped[str] = mapped_column(String(255))
    value: Mapped[int] = mapped_column(BigInteger)
    _table_args = (PrimaryKeyConstraint('rse_id', 'name', name='RSE_LIMITS_PK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='RSE_LIMIT_RSE_ID_FK'), )


class TransferLimit(BASE, ModelBase):
    """Represents limits used to throttle transfer requests"""
    __tablename__ = 'transfer_limits'
    id: Mapped[uuid.UUID] = mapped_column(GUID(), default=utils.generate_uuid)
    rse_expression: Mapped[str] = mapped_column(String(3000))
    activity: Mapped[Optional[str]] = mapped_column(String(50))
    direction: Mapped[TransferLimitDirection] = mapped_column(Enum(TransferLimitDirection, name='TRANSFER_LIMITS_DIRECTION_TYPE_CHK',
                                                                   create_constraint=True,
                                                                   values_callable=lambda obj: [e.value for e in obj]),
                                                              default=TransferLimitDirection.DESTINATION)
    max_transfers: Mapped[Optional[int]] = mapped_column(BigInteger)
    volume: Mapped[Optional[int]] = mapped_column(BigInteger)
    deadline: Mapped[Optional[int]] = mapped_column(BigInteger)
    strategy: Mapped[Optional[str]] = mapped_column(String(25))
    transfers: Mapped[Optional[int]] = mapped_column(BigInteger)
    waitings: Mapped[Optional[int]] = mapped_column(BigInteger)
    _table_args = (PrimaryKeyConstraint('id', name='TRANSFER_LIMITS_PK'),
                   Index('TRANSFER_LIMITS_SELECTORS_IDX', 'rse_expression', 'activity'),
                   CheckConstraint('RSE_EXPRESSION IS NOT NULL', name='TRANSFER_LIMITS_RSE_EXPRESSION_NN'), )


class RSETransferLimit(BASE, ModelBase):
    """Represents the binding of a transfer limit to an RSE as result of TransferLimit.rse_expression dereference"""
    __tablename__ = 'rse_transfer_limits'
    rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    limit_id: Mapped[uuid.UUID] = mapped_column(GUID())
    _table_args = (PrimaryKeyConstraint('rse_id', 'limit_id', name='RSE_TRANSFER_LIMITS_PK'),
                   Index('RSE_TRANSFER_LIMITS_LIMIT_ID_IDX', 'limit_id', 'rse_id'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='RSE_TRANSFER_LIMITS_RSE_ID_FK'),
                   ForeignKeyConstraint(['limit_id'], ['transfer_limits.id'], name='RSE_TRANSFER_LIMITS_LIMIT_ID_FK'), )


class RSEUsage(BASE, ModelBase):
    """Represents location usage"""
    __tablename__ = 'rse_usage'
    rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    source: Mapped[str] = mapped_column(String(255))
    used: Mapped[Optional[int]] = mapped_column(BigInteger)
    free: Mapped[Optional[int]] = mapped_column(BigInteger)
    files: Mapped[Optional[int]] = mapped_column(BigInteger)
    _table_args = (PrimaryKeyConstraint('rse_id', 'source', name='RSE_USAGE_PK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='RSE_USAGE_RSE_ID_FK'), )


class RSEUsageHistory(BASE, ModelBase):
    """Represents location usage history"""
    __tablename__ = 'rse_usage_history'
    rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    source: Mapped[str] = mapped_column(String(255))
    used: Mapped[Optional[int]] = mapped_column(BigInteger)
    free: Mapped[Optional[int]] = mapped_column(BigInteger)
    files: Mapped[Optional[int]] = mapped_column(BigInteger)
    _table_args = (PrimaryKeyConstraint('rse_id', 'source', 'updated_at', name='RSE_USAGE_HISTORY_PK'), )


class UpdatedRSECounter(BASE, ModelBase):
    """Represents the recently updated RSE counters"""
    __tablename__ = 'updated_rse_counters'
    id: Mapped[uuid.UUID] = mapped_column(GUID(), default=utils.generate_uuid)
    rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    files: Mapped[int] = mapped_column(BigInteger)
    bytes: Mapped[int] = mapped_column(BigInteger)
    _table_args = (PrimaryKeyConstraint('id', name='UPDATED_RSE_CNTRS_PK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='UPDATED_RSE_CNTRS_RSE_ID_FK'),
                   Index('UPDATED_RSE_CNTRS_RSE_ID_IDX', 'rse_id'))


class RSEAttrAssociation(BASE, ModelBase):
    """Represents the map between RSEs and tags"""
    __tablename__ = 'rse_attr_map'
    rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    key: Mapped[str] = mapped_column(String(255))
    value: Mapped[Optional[Union[bool, str]]] = mapped_column(BooleanString(255))
    _table_args = (PrimaryKeyConstraint('rse_id', 'key', name='RSE_ATTR_MAP_PK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='RSE_ATTR_MAP_RSE_ID_FK'),
                   Index('RSE_ATTR_MAP_KEY_VALUE_IDX', 'key', 'value'))


class RSEProtocols(BASE, ModelBase):
    """Represents supported protocols of RSEs (Rucio Storage Elements)"""
    __tablename__ = 'rse_protocols'
    rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    scheme: Mapped[str] = mapped_column(String(255))
    hostname: Mapped[str] = mapped_column(String(255), server_default='')  # For protocol without host e.g. POSIX on local file systems localhost is assumed as beeing default
    port: Mapped[int] = mapped_column(Integer, server_default='0')  # like host, for local protocol the port 0 is assumed to be default
    prefix: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    impl: Mapped[str] = mapped_column(String(255), nullable=False)
    read_lan: Mapped[int] = mapped_column(Integer, server_default='0')  # if no value is provided, 0 i.e. not supported is assumed as default value
    write_lan: Mapped[int] = mapped_column(Integer, server_default='0')  # if no value is provided, 0 i.e. not supported is assumed as default value
    delete_lan: Mapped[int] = mapped_column(Integer, server_default='0')  # if no value is provided, 0 i.e. not supported is assumed as default value
    read_wan: Mapped[int] = mapped_column(Integer, server_default='0')  # if no value is provided, 0 i.e. not supported is assumed as default value
    write_wan: Mapped[int] = mapped_column(Integer, server_default='0')  # if no value is provided, 0 i.e. not supported is assumed as default value
    delete_wan: Mapped[int] = mapped_column(Integer, server_default='0')  # if no value is provided, 0 i.e. not supported is assumed as default value
    third_party_copy_read: Mapped[int] = mapped_column(Integer, server_default='0')  # if no value is provided, 0 i.e. not supported is assumed as default value
    third_party_copy_write: Mapped[int] = mapped_column(Integer, server_default='0')  # if no value is provided, 0 i.e. not supported is assumed as default value
    extended_attributes: Mapped[Optional[str]] = mapped_column(String(4000), nullable=True)
    _table_args = (PrimaryKeyConstraint('rse_id', 'scheme', 'hostname', 'port', name='RSE_PROTOCOL_PK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='RSE_PROTOCOL_RSE_ID_FK'),
                   CheckConstraint('IMPL IS NOT NULL', name='RSE_PROTOCOLS_IMPL_NN'))


class RSEQoSAssociation(BASE, ModelBase):
    """Represents the mapping of RSEs"""
    __tablename__ = 'rse_qos_map'
    rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    qos_policy: Mapped[str] = mapped_column(String(64))
    _table_args = (PrimaryKeyConstraint('rse_id', 'qos_policy', name='RSE_QOS_MAP_PK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='RSE_QOS_MAP_RSE_ID_FK'))


class AccountLimit(BASE, ModelBase):
    """Represents account limits"""
    __tablename__ = 'account_limits'
    account: Mapped[InternalAccount] = mapped_column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    bytes: Mapped[Optional[int]] = mapped_column(BigInteger)
    _table_args = (PrimaryKeyConstraint('account', 'rse_id', name='ACCOUNT_LIMITS_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='ACCOUNT_LIMITS_ACCOUNT_FK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='ACCOUNT_LIMITS_RSE_ID_FK'),)


class AccountGlobalLimit(BASE, ModelBase):
    """Represents account limits"""
    __tablename__ = 'account_glob_limits'
    account: Mapped[InternalAccount] = mapped_column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    rse_expression: Mapped[str] = mapped_column(String(3000))
    bytes: Mapped[Optional[int]] = mapped_column(BigInteger)
    _table_args = (PrimaryKeyConstraint('account', 'rse_expression', name='ACCOUNT_GLOBAL_LIMITS_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='ACCOUNT_GLOBAL_LIMITS_ACC_FK'),)


class AccountUsage(BASE, ModelBase):
    """Represents account usage"""
    __tablename__ = 'account_usage'
    account: Mapped[InternalAccount] = mapped_column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    files: Mapped[int] = mapped_column(BigInteger)
    bytes: Mapped[int] = mapped_column(BigInteger)
    _table_args = (PrimaryKeyConstraint('account', 'rse_id', name='ACCOUNT_USAGE_PK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='ACCOUNT_USAGE_ACCOUNT_FK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='ACCOUNT_USAGE_RSES_ID_FK'), )


class AccountUsageHistory(BASE, ModelBase):
    """Represents account usage history"""
    __tablename__ = 'account_usage_history'
    account: Mapped[InternalAccount] = mapped_column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    files: Mapped[int] = mapped_column(BigInteger)
    bytes: Mapped[int] = mapped_column(BigInteger)
    _table_args = (PrimaryKeyConstraint('account', 'rse_id', 'updated_at', name='ACCOUNT_USAGE_HISTORY_PK'),)


class RSEFileAssociation(BASE, ModelBase):
    """Represents the map between locations and files"""
    __tablename__ = 'replicas'
    rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name: Mapped[str] = mapped_column(String(get_schema_value('NAME_LENGTH')))
    bytes: Mapped[int] = mapped_column(BigInteger)
    md5: Mapped[Optional[str]] = mapped_column(String(32))
    adler32: Mapped[Optional[str]] = mapped_column(String(8))
    path: Mapped[Optional[str]] = mapped_column(String(1024))
    state: Mapped[ReplicaState] = mapped_column(Enum(ReplicaState, name='REPLICAS_STATE_CHK',
                                                     create_constraint=True,
                                                     values_callable=lambda obj: [e.value for e in obj]),
                                                default=ReplicaState.UNAVAILABLE)
    lock_cnt: Mapped[int] = mapped_column(Integer, server_default='0')
    accessed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    tombstone: Mapped[Optional[datetime]] = mapped_column(DateTime)
    _table_args = (PrimaryKeyConstraint('scope', 'name', 'rse_id', name='REPLICAS_PK'),
                   ForeignKeyConstraint(['scope', 'name'], ['dids.scope', 'dids.name'], name='REPLICAS_LFN_FK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='REPLICAS_RSE_ID_FK'),
                   CheckConstraint('STATE IS NOT NULL', name='REPLICAS_STATE_NN'),
                   CheckConstraint('bytes IS NOT NULL', name='REPLICAS_SIZE_NN'),
                   CheckConstraint('lock_cnt IS NOT NULL', name='REPLICAS_LOCK_CNT_NN'),
                   Index('REPLICAS_PATH_IDX', 'path', mysql_length=get_schema_value('NAME_LENGTH')),
                   Index('REPLICAS_STATE_IDX', 'state'),
                   Index('REPLICAS_RSE_ID_TOMBSTONE_IDX', 'rse_id', 'tombstone'))


class CollectionReplica(BASE, ModelBase):
    """Represents replicas for datasets/collections"""
    __tablename__ = 'collection_replicas'
    scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name: Mapped[str] = mapped_column(String(get_schema_value('NAME_LENGTH')))
    did_type: Mapped[DIDType] = mapped_column(Enum(DIDType, name='COLLECTION_REPLICAS_TYPE_CHK',
                                                   create_constraint=True,
                                                   values_callable=lambda obj: [e.value for e in obj]))
    rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    bytes: Mapped[int] = mapped_column(BigInteger)
    length: Mapped[int] = mapped_column(BigInteger)
    available_bytes: Mapped[Optional[int]] = mapped_column(BigInteger)
    available_replicas_cnt: Mapped[Optional[int]] = mapped_column(BigInteger)
    state: Mapped[ReplicaState] = mapped_column(Enum(ReplicaState, name='COLLECTION_REPLICAS_STATE_CHK',
                                                     create_constraint=True,
                                                     values_callable=lambda obj: [e.value for e in obj]),
                                                default=ReplicaState.UNAVAILABLE)
    accessed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    _table_args = (PrimaryKeyConstraint('scope', 'name', 'rse_id', name='COLLECTION_REPLICAS_PK'),
                   ForeignKeyConstraint(['scope', 'name'], ['dids.scope', 'dids.name'], name='COLLECTION_REPLICAS_LFN_FK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='COLLECTION_REPLICAS_RSE_ID_FK'),
                   CheckConstraint('STATE IS NOT NULL', name='COLLECTION_REPLICAS_STATE_NN'),
                   CheckConstraint('bytes IS NOT NULL', name='COLLECTION_REPLICAS_SIZE_NN'),
                   Index('COLLECTION_REPLICAS_RSE_ID_IDX', 'rse_id'))


class UpdatedCollectionReplica(BASE, ModelBase):
    """Represents updates to replicas for datasets/collections"""
    __tablename__ = 'updated_col_rep'
    id: Mapped[uuid.UUID] = mapped_column(GUID(), default=utils.generate_uuid)
    scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name: Mapped[str] = mapped_column(String(get_schema_value('NAME_LENGTH')))
    did_type: Mapped[DIDType] = mapped_column(Enum(DIDType, name='UPDATED_COL_REP_TYPE_CHK',
                                                   create_constraint=True,
                                                   values_callable=lambda obj: [e.value for e in obj]))
    rse_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID())
    _table_args = (PrimaryKeyConstraint('id', name='UPDATED_COL_REP_PK'),
                   CheckConstraint('SCOPE IS NOT NULL', name='UPDATED_COL_REP_SCOPE_NN'),
                   CheckConstraint('NAME IS NOT NULL', name='UPDATED_COL_REP_NAME_NN'),
                   Index('UPDATED_COL_REP_SNR_IDX', 'scope', 'name', 'rse_id'))


class RSEFileAssociationHistory(BASE, ModelBase):
    """Represents a short history of the deleted replicas"""
    __tablename__ = 'replicas_history'
    rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name: Mapped[str] = mapped_column(String(get_schema_value('NAME_LENGTH')))
    bytes: Mapped[int] = mapped_column(BigInteger)
    _table_args = (PrimaryKeyConstraint('rse_id', 'scope', 'name', name='REPLICAS_HIST_PK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='REPLICAS_HIST_RSE_ID_FK'),
                   CheckConstraint('bytes IS NOT NULL', name='REPLICAS_HIST_SIZE_NN'))


class ReplicationRule(BASE, ModelBase):
    """Represents data identifier replication rules"""
    __tablename__ = 'rules'
    id: Mapped[uuid.UUID] = mapped_column(GUID(), default=utils.generate_uuid)
    subscription_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID())
    account: Mapped[InternalAccount] = mapped_column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name: Mapped[str] = mapped_column(String(get_schema_value('NAME_LENGTH')))
    did_type: Mapped[DIDType] = mapped_column(Enum(DIDType, name='RULES_DID_TYPE_CHK',
                                                   create_constraint=True,
                                                   values_callable=lambda obj: [e.value for e in obj]))
    state: Mapped[RuleState] = mapped_column(Enum(RuleState, name='RULES_STATE_CHK',
                                                  create_constraint=True,
                                                  values_callable=lambda obj: [e.value for e in obj]),
                                             default=RuleState.REPLICATING)
    error: Mapped[Optional[str]] = mapped_column(String(255))
    rse_expression: Mapped[str] = mapped_column(String(3000))
    copies: Mapped[int] = mapped_column(SmallInteger, server_default='1')
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    weight: Mapped[Optional[str]] = mapped_column(String(255))
    locked: Mapped[bool] = mapped_column(Boolean(name='RULES_LOCKED_CHK', create_constraint=True),
                                         default=False)
    locks_ok_cnt: Mapped[int] = mapped_column(BigInteger, server_default='0')
    locks_replicating_cnt: Mapped[int] = mapped_column(BigInteger, server_default='0')
    locks_stuck_cnt: Mapped[int] = mapped_column(BigInteger, server_default='0')
    source_replica_expression: Mapped[Optional[str]] = mapped_column(String(255))
    activity: Mapped[Optional[str]] = mapped_column(String(50), default='default')
    grouping: Mapped[RuleGrouping] = mapped_column(Enum(RuleGrouping, name='RULES_GROUPING_CHK',
                                                        create_constraint=True,
                                                        values_callable=lambda obj: [e.value for e in obj]),
                                                   default=RuleGrouping.ALL)
    notification: Mapped[RuleNotification] = mapped_column(Enum(RuleNotification, name='RULES_NOTIFICATION_CHK',
                                                                create_constraint=True,
                                                                values_callable=lambda obj: [e.value for e in obj]),
                                                           default=RuleNotification.NO)
    stuck_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    purge_replicas: Mapped[bool] = mapped_column(Boolean(name='RULES_PURGE_REPLICAS_CHK', create_constraint=True),
                                                 default=False)
    ignore_availability: Mapped[bool] = mapped_column(Boolean(name='RULES_IGNORE_AVAILABILITY_CHK', create_constraint=True),
                                                      default=False)
    ignore_account_limit: Mapped[bool] = mapped_column(Boolean(name='RULES_IGNORE_ACCOUNT_LIMIT_CHK', create_constraint=True),
                                                       default=False)
    priority: Mapped[Optional[int]] = mapped_column(Integer)
    comments: Mapped[Optional[str]] = mapped_column(String(255))
    child_rule_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID())
    eol_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    split_container: Mapped[bool] = mapped_column(Boolean(name='RULES_SPLIT_CONTAINER_CHK', create_constraint=True),
                                                  default=False)
    meta: Mapped[Optional[str]] = mapped_column(String(4000))
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
                   Index('RULES_STATE_IDX', 'state'),
                   Index('RULES_CHILD_RULE_ID_IDX', 'child_rule_id'))


class ReplicationRuleHistoryRecent(BASE, ModelBase):
    """Represents replication rules in the recent history"""
    __tablename__ = 'rules_hist_recent'
    id: Mapped[uuid.UUID] = mapped_column(GUID())
    subscription_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID())
    account: Mapped[InternalAccount] = mapped_column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name: Mapped[str] = mapped_column(String(get_schema_value('NAME_LENGTH')))
    did_type: Mapped[DIDType] = mapped_column(Enum(DIDType, name='RULES_HIST_RECENT_DIDTYPE_CHK',
                                                   create_constraint=True,
                                                   values_callable=lambda obj: [e.value for e in obj]))
    state: Mapped[RuleState] = mapped_column(Enum(RuleState, name='RULES_HIST_RECENT_STATE_CHK',
                                                  create_constraint=True,
                                                  values_callable=lambda obj: [e.value for e in obj]))
    error: Mapped[Optional[str]] = mapped_column(String(255))
    rse_expression: Mapped[str] = mapped_column(String(3000))
    copies: Mapped[Optional[int]] = mapped_column(SmallInteger)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    weight: Mapped[Optional[str]] = mapped_column(String(255))
    locked: Mapped[bool] = mapped_column(Boolean())
    locks_ok_cnt: Mapped[Optional[int]] = mapped_column(BigInteger)
    locks_replicating_cnt: Mapped[int] = mapped_column(BigInteger)
    locks_stuck_cnt: Mapped[Optional[int]] = mapped_column(BigInteger)
    source_replica_expression: Mapped[Optional[str]] = mapped_column(String(255))
    activity: Mapped[Optional[str]] = mapped_column(String(50))
    grouping: Mapped[RuleGrouping] = mapped_column(Enum(RuleGrouping, name='RULES_HIST_RECENT_GROUPING_CHK',
                                                        create_constraint=True,
                                                        values_callable=lambda obj: [e.value for e in obj]))
    notification: Mapped[RuleNotification] = mapped_column(Enum(RuleNotification, name='RULES_HIST_RECENT_NOTIFY_CHK',
                                                                create_constraint=True,
                                                                values_callable=lambda obj: [e.value for e in obj]))
    stuck_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    purge_replicas: Mapped[bool] = mapped_column(Boolean())
    ignore_availability: Mapped[bool] = mapped_column(Boolean())
    ignore_account_limit: Mapped[bool] = mapped_column(Boolean())
    priority: Mapped[Optional[int]] = mapped_column(Integer)
    comments: Mapped[Optional[str]] = mapped_column(String(255))
    child_rule_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID())
    eol_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    split_container: Mapped[bool] = mapped_column(Boolean())
    meta: Mapped[Optional[str]] = mapped_column(String(4000))
    __mapper_args__ = {
        'primary_key': [id, locks_replicating_cnt]  # Fake primary key for SQLA
    }
    _table_args = (Index('RULES_HIST_RECENT_ID_IDX', 'id'),
                   Index('RULES_HIST_RECENT_SC_NA_IDX', 'scope', 'name'))


class ReplicationRuleHistory(BASE, ModelBase):
    """Represents replication rules in the longterm history"""
    __tablename__ = 'rules_history'
    id: Mapped[uuid.UUID] = mapped_column(GUID())
    subscription_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID())
    account: Mapped[InternalAccount] = mapped_column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name: Mapped[str] = mapped_column(String(get_schema_value('NAME_LENGTH')))
    did_type: Mapped[DIDType] = mapped_column(Enum(DIDType, name='RULES_HISTORY_DIDTYPE_CHK',
                                                   create_constraint=True,
                                                   values_callable=lambda obj: [e.value for e in obj]))
    state: Mapped[RuleState] = mapped_column(Enum(RuleState, name='RULES_HISTORY_STATE_CHK',
                                                  create_constraint=True,
                                                  values_callable=lambda obj: [e.value for e in obj]))
    error: Mapped[Optional[str]] = mapped_column(String(255))
    rse_expression: Mapped[str] = mapped_column(String(3000))
    copies: Mapped[Optional[int]] = mapped_column(SmallInteger)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    weight: Mapped[Optional[str]] = mapped_column(String(255))
    locked: Mapped[bool] = mapped_column(Boolean())
    locks_ok_cnt: Mapped[Optional[int]] = mapped_column(BigInteger)
    locks_replicating_cnt: Mapped[int] = mapped_column(BigInteger)
    locks_stuck_cnt: Mapped[Optional[int]] = mapped_column(BigInteger)
    source_replica_expression: Mapped[Optional[str]] = mapped_column(String(255))
    activity: Mapped[Optional[str]] = mapped_column(String(50))
    grouping: Mapped[RuleGrouping] = mapped_column(Enum(RuleGrouping, name='RULES_HISTORY_GROUPING_CHK',
                                                        create_constraint=True,
                                                        values_callable=lambda obj: [e.value for e in obj]))
    notification: Mapped[RuleNotification] = mapped_column(Enum(RuleNotification, name='RULES_HISTORY_NOTIFY_CHK',
                                                                create_constraint=True,
                                                                values_callable=lambda obj: [e.value for e in obj]))
    stuck_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    priority: Mapped[Optional[int]] = mapped_column(Integer)
    purge_replicas: Mapped[bool] = mapped_column(Boolean())
    ignore_availability: Mapped[bool] = mapped_column(Boolean())
    ignore_account_limit: Mapped[bool] = mapped_column(Boolean())
    comments: Mapped[Optional[str]] = mapped_column(String(255))
    child_rule_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID())
    eol_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    split_container: Mapped[bool] = mapped_column(Boolean())
    meta: Mapped[Optional[str]] = mapped_column(String(4000))
    __mapper_args__ = {
        'primary_key': [id, locks_replicating_cnt]  # Fake primary key for SQLA
    }
    _table_args = (Index('RULES_HISTORY_SCOPENAME_IDX', 'scope', 'name'), )


class ReplicaLock(BASE, ModelBase):
    """Represents replica locks"""
    __tablename__ = 'locks'
    scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name: Mapped[str] = mapped_column(String(get_schema_value('NAME_LENGTH')))
    rule_id: Mapped[uuid.UUID] = mapped_column(GUID())
    rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    account: Mapped[InternalAccount] = mapped_column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    bytes: Mapped[Optional[int]] = mapped_column(BigInteger)
    state: Mapped[LockState] = mapped_column(Enum(LockState, name='LOCKS_STATE_CHK',
                                                  create_constraint=True,
                                                  values_callable=lambda obj: [e.value for e in obj]),
                                             default=LockState.REPLICATING)
    repair_cnt: Mapped[Optional[int]] = mapped_column(BigInteger)
    _table_args = (PrimaryKeyConstraint('scope', 'name', 'rule_id', 'rse_id', name='LOCKS_PK'),
                   ForeignKeyConstraint(['rule_id'], ['rules.id'], name='LOCKS_RULE_ID_FK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='LOCKS_ACCOUNT_FK'),
                   CheckConstraint('STATE IS NOT NULL', name='LOCKS_STATE_NN'),
                   CheckConstraint('ACCOUNT IS NOT NULL', name='LOCKS_ACCOUNT_NN'),
                   Index('LOCKS_RULE_ID_IDX', 'rule_id'))


class DatasetLock(BASE, ModelBase):
    """Represents dataset locks"""
    __tablename__ = 'dataset_locks'
    scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name: Mapped[str] = mapped_column(String(get_schema_value('NAME_LENGTH')))
    rule_id: Mapped[uuid.UUID] = mapped_column(GUID())
    rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    account: Mapped[InternalAccount] = mapped_column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    state: Mapped[LockState] = mapped_column(Enum(LockState, name='DATASET_LOCKS_STATE_CHK',
                                                  create_constraint=True,
                                                  values_callable=lambda obj: [e.value for e in obj]),
                                             default=LockState.REPLICATING)
    length: Mapped[Optional[int]] = mapped_column(BigInteger)
    bytes: Mapped[Optional[int]] = mapped_column(BigInteger)
    accessed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
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
    id: Mapped[uuid.UUID] = mapped_column(GUID(), default=utils.generate_uuid)
    account: Mapped[InternalAccount] = mapped_column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    files: Mapped[int] = mapped_column(BigInteger)
    bytes: Mapped[int] = mapped_column(BigInteger)
    _table_args = (PrimaryKeyConstraint('id', name='UPDATED_ACCNT_CNTRS_PK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='UPDATED_ACCNT_CNTRS_RSE_ID_FK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='UPDATED_ACCNT_CNTRS_ACCOUNT_FK'),
                   Index('UPDATED_ACCNT_CNTRS_RSE_ID_IDX', 'account', 'rse_id'))


class Request(BASE, ModelBase):
    """Represents a request for a single file with a third party service"""
    __tablename__ = 'requests'
    id: Mapped[uuid.UUID] = mapped_column(GUID(), default=utils.generate_uuid)
    request_type: Mapped[RequestType] = mapped_column(Enum(RequestType, name='REQUESTS_TYPE_CHK',
                                                           create_constraint=True,
                                                           values_callable=lambda obj: [e.value for e in obj]),
                                                      default=RequestType.TRANSFER)
    scope: Mapped[Optional[InternalScope]] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name: Mapped[Optional[str]] = mapped_column(String(get_schema_value('NAME_LENGTH')))
    did_type: Mapped[DIDType] = mapped_column(Enum(DIDType, name='REQUESTS_DIDTYPE_CHK',
                                                   create_constraint=True,
                                                   values_callable=lambda obj: [e.value for e in obj]),
                                              default=DIDType.FILE)
    dest_rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    source_rse_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID())
    attributes: Mapped[Optional[str]] = mapped_column(String(4000))
    state: Mapped[RequestState] = mapped_column(Enum(RequestState, name='REQUESTS_STATE_CHK',
                                                     create_constraint=True,
                                                     values_callable=lambda obj: [e.value for e in obj]),
                                                default=RequestState.QUEUED)
    external_id: Mapped[Optional[str]] = mapped_column(String(64))
    external_host: Mapped[Optional[str]] = mapped_column(String(256))
    retry_count: Mapped[int] = mapped_column(Integer(), server_default='0')
    err_msg: Mapped[Optional[str]] = mapped_column(String(4000))
    previous_attempt_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID())
    rule_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID())
    activity: Mapped[Optional[str]] = mapped_column(String(50), default='default')
    bytes: Mapped[Optional[int]] = mapped_column(BigInteger)
    md5: Mapped[Optional[str]] = mapped_column(String(32))
    adler32: Mapped[Optional[str]] = mapped_column(String(8))
    dest_url: Mapped[Optional[str]] = mapped_column(String(2048))
    submitted_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    transferred_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    estimated_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    submitter_id: Mapped[Optional[int]] = mapped_column(Integer)
    estimated_started_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    estimated_transferred_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    staging_started_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    staging_finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    account: Mapped[Optional[InternalAccount]] = mapped_column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    requested_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    last_processed_by: Mapped[Optional[str]] = mapped_column(String(64))
    last_processed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    priority: Mapped[Optional[int]] = mapped_column(Integer)
    transfertool: Mapped[Optional[str]] = mapped_column(String(64))
    _table_args = (PrimaryKeyConstraint('id', name='REQUESTS_PK'),
                   ForeignKeyConstraint(['scope', 'name'], ['dids.scope', 'dids.name'], name='REQUESTS_DID_FK'),
                   ForeignKeyConstraint(['dest_rse_id'], ['rses.id'], name='REQUESTS_RSES_FK'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='REQUESTS_ACCOUNT_FK'),
                   CheckConstraint('dest_rse_id IS NOT NULL', name='REQUESTS_RSE_ID_NN'),
                   Index('REQUESTS_SCOPE_NAME_RSE_IDX', 'scope', 'name', 'dest_rse_id', 'request_type'),
                   Index('REQUESTS_TYP_STA_UPD_IDX_OLD', 'request_type', 'state', 'updated_at'),
                   Index('REQUESTS_TYP_STA_UPD_IDX', 'request_type', 'state', 'activity'),
                   Index('REQUESTS_RULEID_IDX', 'rule_id'),
                   Index('REQUESTS_EXTERNALID_UQ', 'external_id'),
                   Index('REQUESTS_DEST_RSE_ID_IDX', 'dest_rse_id'),
                   Index('REQUESTS_TYP_STA_TRA_ACT_IDX', 'request_type', 'state', 'transfertool', 'activity'))


class TransferHop(BASE, ModelBase):
    """Represents source files for transfers"""
    __tablename__ = 'transfer_hops'
    request_id: Mapped[uuid.UUID] = mapped_column(GUID())
    next_hop_request_id: Mapped[uuid.UUID] = mapped_column(GUID())
    initial_request_id: Mapped[uuid.UUID] = mapped_column(GUID())
    _table_args = (PrimaryKeyConstraint('request_id', 'next_hop_request_id', 'initial_request_id', name='TRANSFER_HOPS_PK'),
                   ForeignKeyConstraint(['initial_request_id'], ['requests.id'], name='TRANSFER_HOPS_INIT_REQ_ID_FK'),
                   ForeignKeyConstraint(['request_id'], ['requests.id'], name='TRANSFER_HOPS_REQ_ID_FK'),
                   ForeignKeyConstraint(['next_hop_request_id'], ['requests.id'], name='TRANSFER_HOPS_NH_REQ_ID_FK'),
                   Index('TRANSFER_HOPS_INITIAL_REQ_IDX', 'initial_request_id'),
                   Index('TRANSFER_HOPS_NH_REQ_IDX', 'next_hop_request_id'))


class RequestHistory(BASE, ModelBase):
    """Represents request history"""
    __tablename__ = 'requests_history'
    id: Mapped[uuid.UUID] = mapped_column(GUID(), default=utils.generate_uuid)
    request_type: Mapped[RequestType] = mapped_column(Enum(RequestType, name='REQUESTS_HIST_TYPE_CHK',
                                                           create_constraint=True,
                                                           values_callable=lambda obj: [e.value for e in obj]),
                                                      default=RequestType.TRANSFER)
    scope: Mapped[Optional[InternalScope]] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name: Mapped[Optional[str]] = mapped_column(String(get_schema_value('NAME_LENGTH')))
    did_type: Mapped[DIDType] = mapped_column(Enum(DIDType, name='REQUESTS_HIST_DIDTYPE_CHK',
                                                   create_constraint=True,
                                                   values_callable=lambda obj: [e.value for e in obj]),
                                              default=DIDType.FILE)
    dest_rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    source_rse_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID())
    attributes: Mapped[Optional[str]] = mapped_column(String(4000))
    state: Mapped[RequestState] = mapped_column(Enum(RequestState, name='REQUESTS_HIST_STATE_CHK',
                                                     create_constraint=True,
                                                     values_callable=lambda obj: [e.value for e in obj]),
                                                default=RequestState.QUEUED)
    external_id: Mapped[Optional[str]] = mapped_column(String(64))
    external_host: Mapped[Optional[str]] = mapped_column(String(256))
    retry_count: Mapped[int] = mapped_column(Integer(), server_default='0')
    err_msg: Mapped[Optional[str]] = mapped_column(String(4000))
    previous_attempt_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID())
    rule_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID())
    activity: Mapped[Optional[str]] = mapped_column(String(50), default='default')
    bytes: Mapped[Optional[int]] = mapped_column(BigInteger)
    md5: Mapped[Optional[str]] = mapped_column(String(32))
    adler32: Mapped[Optional[str]] = mapped_column(String(8))
    dest_url: Mapped[Optional[str]] = mapped_column(String(2048))
    submitted_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    transferred_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    estimated_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    submitter_id: Mapped[Optional[int]] = mapped_column(Integer)
    estimated_started_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    estimated_transferred_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    staging_started_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    staging_finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    account: Mapped[Optional[InternalAccount]] = mapped_column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    requested_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    priority: Mapped[Optional[int]] = mapped_column(Integer)
    transfertool: Mapped[Optional[str]] = mapped_column(String(64))
    __mapper_args__ = {
        'primary_key': [id]  # Fake primary key for SQLA
    }
    _table_args = (Index('REQ_HIST_SCOPE_NAME_RSE_IDX', 'scope', 'name', 'dest_rse_id'),
                   )


class Source(BASE, ModelBase):
    """Represents source files for transfers"""
    __tablename__ = 'sources'
    request_id: Mapped[uuid.UUID] = mapped_column(GUID())
    scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name: Mapped[str] = mapped_column(String(get_schema_value('NAME_LENGTH')))
    rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    dest_rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    url: Mapped[Optional[str]] = mapped_column(String(2048))
    bytes: Mapped[Optional[int]] = mapped_column(BigInteger)
    ranking: Mapped[Optional[int]] = mapped_column(Integer())
    is_using: Mapped[bool] = mapped_column(Boolean(), default=False)
    _table_args = (PrimaryKeyConstraint('request_id', 'rse_id', 'scope', 'name', name='SOURCES_PK'),
                   ForeignKeyConstraint(['request_id'], ['requests.id'], name='SOURCES_REQ_ID_FK'),
                   ForeignKeyConstraint(['scope', 'name', 'rse_id'], ['replicas.scope', 'replicas.name', 'replicas.rse_id'], name='SOURCES_REPLICA_FK'),
                   ForeignKeyConstraint(['rse_id'], ['rses.id'], name='SOURCES_RSES_FK'),
                   ForeignKeyConstraint(['dest_rse_id'], ['rses.id'], name='SOURCES_DEST_RSES_FK'),
                   Index('SOURCES_SRC_DST_IDX', 'rse_id', 'dest_rse_id'),
                   Index('SOURCES_SC_NM_DST_IDX', 'scope', 'rse_id', 'name'),
                   Index('SOURCES_DEST_RSEID_IDX', 'dest_rse_id'))


class SourceHistory(BASE, ModelBase):
    """Represents history of source files for transfers"""
    __tablename__ = 'sources_history'
    request_id: Mapped[uuid.UUID] = mapped_column(GUID())
    scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name: Mapped[str] = mapped_column(String(get_schema_value('NAME_LENGTH')))
    rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    dest_rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    url: Mapped[Optional[str]] = mapped_column(String(2048))
    bytes: Mapped[Optional[int]] = mapped_column(BigInteger)
    ranking: Mapped[Optional[int]] = mapped_column(Integer())
    is_using: Mapped[bool] = mapped_column(Boolean(), default=False)
    __mapper_args__ = {
        'primary_key': [request_id]  # Fake primary key for SQLA
    }
    _table_args = (Index('SOURCES_HIST_REQID_IDX', 'request_id'),
                   )


class Distance(BASE, ModelBase):
    """Represents distance between rses"""
    __tablename__ = 'distances'
    src_rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    dest_rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    distance: Mapped[Optional[int]] = mapped_column(Integer())
    _table_args = (PrimaryKeyConstraint('src_rse_id', 'dest_rse_id', name='DISTANCES_PK'),
                   ForeignKeyConstraint(['src_rse_id'], ['rses.id'], name='DISTANCES_SRC_RSES_FK'),
                   ForeignKeyConstraint(['dest_rse_id'], ['rses.id'], name='DISTANCES_DEST_RSES_FK'),
                   Index('DISTANCES_DEST_RSEID_IDX', 'dest_rse_id'))


class TransferStats(BASE, ModelBase):
    """Represents counters for transfer link usage"""
    __tablename__ = 'transfer_stats'
    id: Mapped[uuid.UUID] = mapped_column(GUID(), default=utils.generate_uuid)
    resolution: Mapped[int] = mapped_column(Integer)
    timestamp: Mapped[datetime] = mapped_column(DateTime)
    dest_rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    src_rse_id: Mapped[uuid.UUID] = mapped_column(GUID())
    activity: Mapped[Optional[str]] = mapped_column(String(50))
    files_done: Mapped[int] = mapped_column(BigInteger)
    bytes_done: Mapped[int] = mapped_column(BigInteger)
    files_failed: Mapped[int] = mapped_column(BigInteger)
    _table_args = (PrimaryKeyConstraint('id', name='TRANSFER_STATS_PK'),
                   ForeignKeyConstraint(['dest_rse_id'], ['rses.id'], name='TRANSFER_STATS_DEST_RSE_FK'),
                   ForeignKeyConstraint(['src_rse_id'], ['rses.id'], name='TRANSFER_STATS_SRC_RSE_FK'),
                   Index('TRANSFER_STATS_KEY_IDX', 'resolution', 'timestamp', 'dest_rse_id', 'src_rse_id', 'activity'))


class Subscription(BASE, ModelBase):
    """Represents a subscription"""
    __tablename__ = 'subscriptions'
    id: Mapped[uuid.UUID] = mapped_column(GUID(), default=utils.generate_uuid)
    name: Mapped[str] = mapped_column(String(64))
    filter: Mapped[Optional[str]] = mapped_column(String(4000))
    replication_rules: Mapped[Optional[str]] = mapped_column(String(4000))
    policyid: Mapped[int] = mapped_column(SmallInteger, server_default='0')
    state: Mapped[SubscriptionState] = mapped_column(Enum(SubscriptionState, name='SUBSCRIPTIONS_STATE_CHK',
                                                          create_constraint=True,
                                                          values_callable=lambda obj: [e.value for e in obj]),
                                                     default=SubscriptionState.ACTIVE)
    last_processed: Mapped[Optional[datetime]] = mapped_column(DateTime, default=datetime.utcnow())
    account: Mapped[InternalAccount] = mapped_column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    lifetime: Mapped[Optional[datetime]] = mapped_column(DateTime)
    comments: Mapped[Optional[str]] = mapped_column(String(4000))
    retroactive: Mapped[bool] = mapped_column(Boolean(name='SUBSCRIPTIONS_RETROACTIVE_CHK', create_constraint=True),
                                              default=False)
    expired_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    _table_args = (PrimaryKeyConstraint('id', name='SUBSCRIPTIONS_PK'),
                   UniqueConstraint('name', 'account', name='SUBSCRIPTIONS_NAME_ACCOUNT_UQ'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='SUBSCRIPTIONS_ACCOUNT_FK'),
                   CheckConstraint('RETROACTIVE IS NOT NULL', name='SUBSCRIPTIONS_RETROACTIVE_NN'),
                   CheckConstraint('ACCOUNT IS NOT NULL', name='SUBSCRIPTIONS_ACCOUNT_NN'),
                   Index('SUBSCRIPTIONS_STATE_IDX', 'state'))  # Under Oracle this is a FB index


class SubscriptionHistory(BASE, ModelBase):
    """Represents a subscription history"""
    __tablename__ = 'subscriptions_history'
    id: Mapped[uuid.UUID] = mapped_column(GUID(), default=utils.generate_uuid)
    name: Mapped[str] = mapped_column(String(64))
    filter: Mapped[Optional[str]] = mapped_column(String(4000))
    replication_rules: Mapped[Optional[str]] = mapped_column(String(4000))
    policyid: Mapped[int] = mapped_column(SmallInteger, server_default='0')
    state: Mapped[SubscriptionState] = mapped_column(Enum(SubscriptionState, name='SUBSCRIPTIONS_HIST_STATE_CHK',
                                                          create_constraint=True,
                                                          values_callable=lambda obj: [e.value for e in obj]),
                                                     default=SubscriptionState.ACTIVE)
    last_processed: Mapped[Optional[datetime]] = mapped_column(DateTime, default=datetime.utcnow())
    account: Mapped[InternalAccount] = mapped_column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    lifetime: Mapped[Optional[datetime]] = mapped_column(DateTime)
    comments: Mapped[Optional[str]] = mapped_column(String(4000))
    retroactive: Mapped[bool] = mapped_column(Boolean(name='SUBS_HISTORY_RETROACTIVE_CHK', create_constraint=True),
                                              default=False)
    expired_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    _table_args = (PrimaryKeyConstraint('id', 'updated_at', name='SUBSCRIPTIONS_PK'),)


class Token(BASE, ModelBase):
    """Represents the authentication tokens and their lifetime"""
    __tablename__ = 'tokens'
    token: Mapped[str] = mapped_column(String(3072))  # account-identity-appid-uuid -> max length: (+ 30 1 255 1 32 1 32)
    account: Mapped[InternalAccount] = mapped_column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    refresh_token: Mapped[Optional[str]] = mapped_column(String(3072), default=None)
    refresh: Mapped[bool] = mapped_column(Boolean(name='TOKENS_REFRESH_CHK', create_constraint=True),
                                          default=False)
    refresh_start: Mapped[Optional[datetime]] = mapped_column(DateTime, default=None)
    refresh_expired_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=None)
    refresh_lifetime: Mapped[Optional[int]] = mapped_column(Integer())
    oidc_scope: Mapped[Optional[str]] = mapped_column(String(2048), default=None)  # scopes define the specific actions applications can be allowed to do on a user's behalf
    identity: Mapped[Optional[str]] = mapped_column(String(2048))
    audience: Mapped[Optional[str]] = mapped_column(String(315), default=None)
    expired_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.utcnow() + timedelta(seconds=3600))  # one hour lifetime by default
    ip: Mapped[Optional[str]] = mapped_column(String(39), nullable=True)
    _table_args = (PrimaryKeyConstraint('token', name='TOKENS_TOKEN_PK'),  # not supported for primary key constraint mysql_length=255
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='TOKENS_ACCOUNT_FK'),
                   CheckConstraint('EXPIRED_AT IS NOT NULL', name='TOKENS_EXPIRED_AT_NN'),
                   Index('TOKENS_ACCOUNT_EXPIRED_AT_IDX', 'account', 'expired_at'))


class OAuthRequest(BASE, ModelBase):
    """Represents the authentication session parameters of OAuth 2.0 requests"""
    __tablename__ = 'oauth_requests'
    account: Mapped[InternalAccount] = mapped_column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    state: Mapped[str] = mapped_column(String(50))
    nonce: Mapped[Optional[str]] = mapped_column(String(50))
    access_msg: Mapped[Optional[str]] = mapped_column(String(2048))
    redirect_msg: Mapped[Optional[str]] = mapped_column(String(2048))
    refresh_lifetime: Mapped[Optional[int]] = mapped_column(Integer())
    ip: Mapped[Optional[str]] = mapped_column(String(39), nullable=True)
    expired_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.utcnow() + timedelta(seconds=600))  # 10 min lifetime by default
    _table_args = (PrimaryKeyConstraint('state', name='OAUTH_REQUESTS_STATE_PK'),
                   CheckConstraint('EXPIRED_AT IS NOT NULL', name='OAUTH_REQUESTS_EXPIRED_AT_NN'),
                   Index('OAUTH_REQUESTS_ACC_EXP_AT_IDX', 'account', 'expired_at'),
                   Index('OAUTH_REQUESTS_ACCESS_MSG_IDX', 'access_msg'))


class Message(BASE, ModelBase):
    """Represents the event messages"""
    __tablename__ = 'messages'
    id: Mapped[uuid.UUID] = mapped_column(GUID(), default=utils.generate_uuid)
    event_type: Mapped[str] = mapped_column(String(256))
    payload: Mapped[str] = mapped_column(String(4000))
    payload_nolimit: Mapped[Optional[str]] = mapped_column(Text)
    services: Mapped[Optional[str]] = mapped_column(String(256))
    _table_args = (PrimaryKeyConstraint('id', name='MESSAGES_ID_PK'),
                   CheckConstraint('EVENT_TYPE IS NOT NULL', name='MESSAGES_EVENT_TYPE_NN'),
                   CheckConstraint('PAYLOAD IS NOT NULL', name='MESSAGES_PAYLOAD_NN'),
                   Index('MESSAGES_SERVICES_IDX', 'services', 'event_type'))


class MessageHistory(BASE, ModelBase):
    """Represents the history of event messages"""
    __tablename__ = 'messages_history'
    id: Mapped[uuid.UUID] = mapped_column(GUID())
    event_type: Mapped[Optional[str]] = mapped_column(String(1024))
    payload: Mapped[Optional[str]] = mapped_column(String(4000))
    payload_nolimit: Mapped[Optional[str]] = mapped_column(Text)
    services: Mapped[Optional[str]] = mapped_column(String(2048))
    __mapper_args__ = {
        'primary_key': [id]  # Fake primary key for SQLA
    }
    _table_args = ()  # PrimaryKeyConstraint('id', name='MESSAGES_HIST_ID_PK'),)  # PK needed for SQLA only


class AlembicVersion(BASE):
    """Table used to pinpoint actual database schema release."""
    __tablename__ = "alembic_version"
    version_num: Mapped[str] = mapped_column(String(32), primary_key=True, nullable=False)


class Config(BASE, ModelBase):
    """Represents the configuration"""
    __tablename__ = 'configs'
    section: Mapped[str] = mapped_column(String(128))
    opt: Mapped[str] = mapped_column(String(128))
    value: Mapped[Optional[str]] = mapped_column(String(4000))
    _table_args = (PrimaryKeyConstraint('section', 'opt', name='CONFIGS_PK'), )


class ConfigHistory(BASE, ModelBase):
    """Represents the configuration"""
    __tablename__ = 'configs_history'
    section: Mapped[str] = mapped_column(String(128))
    opt: Mapped[str] = mapped_column(String(128))
    value: Mapped[Optional[str]] = mapped_column(String(4000))
    __mapper_args__ = {
        'primary_key': [section, opt]  # Fake primary key for SQLA
    }
    _table_args = ()


class Heartbeats(BASE, ModelBase):
    """Represents the status and heartbeat of the running daemons and services"""
    __tablename__ = 'heartbeats'
    executable: Mapped[str] = mapped_column(String(64))  # SHA-2
    readable: Mapped[Optional[str]] = mapped_column(String(4000))
    hostname: Mapped[str] = mapped_column(String(128))
    pid: Mapped[int] = mapped_column(Integer, autoincrement=False)
    thread_id: Mapped[int] = mapped_column(BigInteger, autoincrement=False)
    thread_name: Mapped[Optional[str]] = mapped_column(String(64))
    payload: Mapped[Optional[str]] = mapped_column(String(3000))
    _table_args = (PrimaryKeyConstraint('executable', 'hostname', 'pid', 'thread_id', name='HEARTBEATS_PK'), )


class NamingConvention(BASE, ModelBase):
    """Represents naming conventions for name within a scope"""
    __tablename__ = 'naming_conventions'
    scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    regexp: Mapped[Optional[str]] = mapped_column(String(255))
    convention_type: Mapped[KeyType] = mapped_column(Enum(KeyType, name='CVT_TYPE_CHK',
                                                          create_constraint=True,
                                                          values_callable=lambda obj: [e.value for e in obj]))
    _table_args = (PrimaryKeyConstraint('scope', name='NAMING_CONVENTIONS_PK'),
                   ForeignKeyConstraint(['scope'], ['scopes.scope'], name='NAMING_CONVENTIONS_SCOPE_FK'))


class LifetimeExceptions(BASE, ModelBase):
    """Represents the exceptions to the lifetime model"""
    __tablename__ = 'lifetime_except'
    id: Mapped[uuid.UUID] = mapped_column(GUID(), default=utils.generate_uuid)
    scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name: Mapped[str] = mapped_column(String(get_schema_value('NAME_LENGTH')))
    did_type: Mapped[DIDType] = mapped_column(Enum(DIDType, name='LIFETIME_EXCEPT_TYPE_CHK',
                                                   create_constraint=True,
                                                   values_callable=lambda obj: [e.value for e in obj]))
    account: Mapped[InternalAccount] = mapped_column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    pattern: Mapped[Optional[str]] = mapped_column(String(255))
    comments: Mapped[Optional[str]] = mapped_column(String(4000))
    state: Mapped[LifetimeExceptionsState] = mapped_column(Enum(LifetimeExceptionsState, name='LIFETIME_EXCEPT_STATE_CHK',
                                                                create_constraint=True,
                                                                values_callable=lambda obj: [e.value for e in obj]))
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    _table_args = (PrimaryKeyConstraint('id', 'scope', 'name', 'did_type', 'account', name='LIFETIME_EXCEPT_PK'),
                   CheckConstraint('SCOPE IS NOT NULL', name='LIFETIME_EXCEPT_SCOPE_NN'),
                   CheckConstraint('NAME IS NOT NULL', name='LIFETIME_EXCEPT_NAME_NN'),
                   CheckConstraint('DID_TYPE IS NOT NULL', name='LIFETIME_EXCEPT_DID_TYPE_NN'),
                   ForeignKeyConstraint(['account'], ['accounts.account'], name='LIFETIME_EXCEPT_ACCOUNT_FK'))


class VO(BASE, ModelBase):
    """Represents the VOS in a MultiVO setup"""
    __tablename__ = 'vos'
    vo: Mapped[str] = mapped_column(String(3))
    description: Mapped[Optional[str]] = mapped_column(String(255))
    email: Mapped[Optional[str]] = mapped_column(String(255))
    _table_args = (PrimaryKeyConstraint('vo', name='VOS_PK'), )


class DidsFollowed(BASE, ModelBase):
    """Represents the datasets followed by an user"""
    __tablename__ = 'dids_followed'
    scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name: Mapped[str] = mapped_column(String(get_schema_value('NAME_LENGTH')))
    account: Mapped[InternalAccount] = mapped_column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    did_type: Mapped[DIDType] = mapped_column(Enum(DIDType, name='DIDS_FOLLOWED_TYPE_CHK',
                                                   create_constraint=True,
                                                   values_callable=lambda obj: [e.value for e in obj]))
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
    scope: Mapped[InternalScope] = mapped_column(InternalScopeString(get_schema_value('SCOPE_LENGTH')))
    name: Mapped[str] = mapped_column(String(get_schema_value('NAME_LENGTH')))
    account: Mapped[InternalAccount] = mapped_column(InternalAccountString(get_schema_value('ACCOUNT_LENGTH')))
    did_type: Mapped[DIDType] = mapped_column(Enum(DIDType, name='DIDS_FOLLOWED_EVENTS_TYPE_CHK',
                                                   create_constraint=True,
                                                   values_callable=lambda obj: [e.value for e in obj]))
    event_type: Mapped[Optional[str]] = mapped_column(String(1024))
    payload: Mapped[Optional[str]] = mapped_column(Text)
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
              AccountUsageHistory,
              AlembicVersion,
              BadReplicas,
              CollectionReplica,
              Config,
              ConfigHistory,
              ConstituentAssociation,
              ConstituentAssociationHistory,
              DataIdentifierAssociation,
              DataIdentifierAssociationHistory,
              DIDMetaConventionsKey,
              DIDMetaConventionsConstraints,
              DataIdentifier,
              DidMeta,
              VirtualPlacements,
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
              QuarantinedReplicaHistory,
              RSE,
              RSEAttrAssociation,
              RSEFileAssociation,
              RSEFileAssociationHistory,
              RSELimit,
              RSEProtocols,
              RSEQoSAssociation,
              RSEUsage,
              RSEUsageHistory,
              ReplicaLock,
              ReplicationRule,
              ReplicationRule,
              ReplicationRuleHistory,
              ReplicationRuleHistoryRecent,
              Request,
              RequestHistory,
              TransferHop,
              Scope,
              Source,
              SourceHistory,
              Subscription,
              SubscriptionHistory,
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
              AccountUsageHistory,
              AlembicVersion,
              BadReplicas,
              CollectionReplica,
              Config,
              ConfigHistory,
              ConstituentAssociation,
              ConstituentAssociationHistory,
              DataIdentifierAssociation,
              DataIdentifierAssociationHistory,
              DIDMetaConventionsKey,
              DIDMetaConventionsConstraints,
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
              QuarantinedReplicaHistory,
              RSE,
              RSEAttrAssociation,
              RSEFileAssociation,
              RSEFileAssociationHistory,
              RSELimit,
              RSEProtocols,
              RSEQoSAssociation,
              RSEUsage,
              RSEUsageHistory,
              ReplicaLock,
              ReplicationRule,
              ReplicationRule,
              ReplicationRuleHistory,
              ReplicationRuleHistoryRecent,
              Request,
              RequestHistory,
              TransferHop,
              Scope,
              Source,
              SourceHistory,
              Subscription,
              SubscriptionHistory,
              Token,
              UpdatedAccountCounter,
              UpdatedDID,
              UpdatedRSECounter,
              UpdatedCollectionReplica,
              VO)

    for model in models:
        model.metadata.drop_all(engine)   # pylint: disable=maybe-no-member
