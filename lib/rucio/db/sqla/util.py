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

import logging
from datetime import datetime
from hashlib import sha256
from os import urandom
from typing import TYPE_CHECKING

import sqlalchemy
from alembic import command, op
from alembic.config import Config
from dogpile.cache.api import NoValue
from sqlalchemy import func, inspect, Column, PrimaryKeyConstraint
from sqlalchemy.dialects.postgresql.base import PGInspector
from sqlalchemy.exc import IntegrityError, DatabaseError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.schema import CreateSchema, MetaData, Table, CreateTable, DropTable, ForeignKeyConstraint, DropConstraint
from sqlalchemy.sql.ddl import DropSchema
from sqlalchemy.sql.expression import select, text

from rucio import alembicrevision
from rucio.common.cache import make_region_memcached
from rucio.common.config import config_get, config_get_list
from rucio.common.schema import get_schema_value
from rucio.common.types import InternalAccount
from rucio.common.utils import generate_uuid
from rucio.core.account_counter import create_counters_for_new_account
from rucio.db.sqla import models
from rucio.db.sqla.constants import AccountStatus, AccountType, IdentityType
from rucio.db.sqla.session import get_engine, get_session, get_dump_engine
from rucio.db.sqla.types import InternalScopeString, String

if TYPE_CHECKING:
    from typing import Optional, Union  # noqa: F401
    from sqlalchemy.orm import Session  # noqa: F401
    from sqlalchemy.engine import Inspector  # noqa: F401

REGION = make_region_memcached(expiration_time=600, memcached_expire_time=3660)


def build_database():
    """ Applies the schema to the database. Run this command once to build the database. """
    engine = get_engine()

    schema = config_get('database', 'schema', raise_exception=False, check_config_table=False)
    if schema:
        print('Schema set in config, trying to create schema:', schema)
        try:
            engine.execute(CreateSchema(schema))
        except Exception as e:
            print('Cannot create schema, please validate manually if schema creation is needed, continuing:', e)

    models.register_models(engine)

    # Put the database under version control
    alembic_cfg = Config(config_get('alembic', 'cfg'))
    command.stamp(alembic_cfg, "head")


def dump_schema():
    """ Creates a schema dump to a specific database. """
    engine = get_dump_engine()
    models.register_models(engine)


def destroy_database():
    """ Removes the schema from the database. Only useful for test cases or malicious intents. """
    engine = get_engine()

    try:
        models.unregister_models(engine)
    except Exception as e:
        print('Cannot destroy schema -- assuming already gone, continuing:', e)


def drop_everything():
    """
    Pre-gather all named constraints and table names, and drop everything.
    This is better than using metadata.reflect(); metadata.drop_all()
    as it handles cyclical constraints between tables.
    Ref. https://github.com/sqlalchemy/sqlalchemy/wiki/DropEverything
    """
    engine = get_engine()

    # the transaction only applies if the DB supports
    # transactional DDL, i.e. Postgresql, MS SQL Server
    with engine.begin() as conn:

        inspector = inspect(conn)  # type: Union[Inspector, PGInspector]

        for tname, fkcs in reversed(
                inspector.get_sorted_table_and_fkc_names(schema='*')):
            if tname:
                drop_table_stmt = DropTable(Table(tname, MetaData(), schema='*'))
                conn.execute(drop_table_stmt)
            elif fkcs:
                if not engine.dialect.supports_alter:
                    continue
                for tname, fkc in fkcs:
                    fk_constraint = ForeignKeyConstraint((), (), name=fkc)
                    Table(tname, MetaData(), fk_constraint)
                    drop_constraint_stmt = DropConstraint(fk_constraint)
                    conn.execute(drop_constraint_stmt)

        schema = config_get('database', 'schema', raise_exception=False)
        if schema:
            conn.execute(DropSchema(schema, cascade=True))

        if engine.dialect.name == 'postgresql':
            assert isinstance(inspector, PGInspector), 'expected a PGInspector'
            for enum in inspector.get_enums(schema='*'):
                sqlalchemy.Enum(**enum).drop(bind=conn)


def create_base_vo():
    """ Creates the base VO """

    s = get_session()

    vo = models.VO(vo='def', description='Default base VO', email='N/A')

    s.add_all([vo])
    s.commit()


def create_root_account(create_counters=True):
    """
    Inserts the default root account to an existing database. Make sure to change the default password later.

    :param create_counters: If True, create counters for the new account at existing RSEs.
    """

    multi_vo = bool(config_get('common', 'multi_vo', False, False))

    up_id = 'ddmlab'
    up_pwd = 'secret'
    up_email = 'ph-adp-ddm-lab@cern.ch'
    x509_id = '/C=CH/ST=Geneva/O=CERN/OU=PH-ADP-CO/CN=DDMLAB Client Certificate/emailAddress=ph-adp-ddm-lab@cern.ch'
    x509_email = 'ph-adp-ddm-lab@cern.ch'
    gss_id = 'ddmlab@CERN.CH'
    gss_email = 'ph-adp-ddm-lab@cern.ch'
    ssh_id = 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq5LySllrQFpPL614sulXQ7wnIr1aGhGtl8b+HCB/'\
             '0FhMSMTHwSjX78UbfqEorZV16rXrWPgUpvcbp2hqctw6eCbxwqcgu3uGWaeS5A0iWRw7oXUh6ydn'\
             'Vy89zGzX1FJFFDZ+AgiZ3ytp55tg1bjqqhK1OSC0pJxdNe878TRVVo5MLI0S/rZY2UovCSGFaQG2'\
             'iLj14wz/YqI7NFMUuJFR4e6xmNsOP7fCZ4bGMsmnhR0GmY0dWYTupNiP5WdYXAfKExlnvFLTlDI5'\
             'Mgh4Z11NraQ8pv4YE1woolYpqOc/IMMBBXFniTT4tC7cgikxWb9ZmFe+r4t6yCDpX4IL8L5GOQ== ddmlab'
    ssh_email = 'ph-adp-ddm-lab@cern.ch'

    try:
        up_id = config_get('bootstrap', 'userpass_identity')
        up_pwd = config_get('bootstrap', 'userpass_pwd')
        up_email = config_get('bootstrap', 'userpass_email')
        x509_id = config_get('bootstrap', 'x509_identity')
        x509_email = config_get('bootstrap', 'x509_email')
        gss_id = config_get('bootstrap', 'gss_identity')
        gss_email = config_get('bootstrap', 'gss_email')
        ssh_id = config_get('bootstrap', 'ssh_identity')
        ssh_email = config_get('bootstrap', 'ssh_email')
    except:
        pass
        # print 'Config values are missing (check rucio.cfg{.template}). Using hardcoded defaults.'

    s = get_session()

    if multi_vo:
        access = 'super_root'
    else:
        access = 'root'

    account = models.Account(account=InternalAccount(access, 'def'), account_type=AccountType.SERVICE, status=AccountStatus.ACTIVE)

    salt = urandom(255)
    salted_password = salt + up_pwd.encode()
    hashed_password = sha256(salted_password).hexdigest()
    identity1 = models.Identity(identity=up_id, identity_type=IdentityType.USERPASS, password=hashed_password, salt=salt, email=up_email)
    iaa1 = models.IdentityAccountAssociation(identity=identity1.identity, identity_type=identity1.identity_type, account=account.account, is_default=True)

    # X509 authentication
    identity2 = models.Identity(identity=x509_id, identity_type=IdentityType.X509, email=x509_email)
    iaa2 = models.IdentityAccountAssociation(identity=identity2.identity, identity_type=identity2.identity_type, account=account.account, is_default=True)

    # GSS authentication
    identity3 = models.Identity(identity=gss_id, identity_type=IdentityType.GSS, email=gss_email)
    iaa3 = models.IdentityAccountAssociation(identity=identity3.identity, identity_type=identity3.identity_type, account=account.account, is_default=True)

    # SSH authentication
    identity4 = models.Identity(identity=ssh_id, identity_type=IdentityType.SSH, email=ssh_email)
    iaa4 = models.IdentityAccountAssociation(identity=identity4.identity, identity_type=identity4.identity_type, account=account.account, is_default=True)

    # Account counters
    if create_counters:
        create_counters_for_new_account(account=account.account, session=s)

    # Apply
    for identity in [identity1, identity2, identity3, identity4]:
        try:
            s.add(identity)
            s.commit()
        except IntegrityError:
            # Identities may already be in the DB when running multi-VO conversion
            s.rollback()
    s.add(account)
    s.commit()
    s.add_all([iaa1, iaa2, iaa3, iaa4])
    s.commit()


def get_db_time():
    """ Gives the utc time on the db. """
    s = get_session()
    try:
        storage_date_format = None
        if s.bind.dialect.name == 'oracle':
            query = select([text("sys_extract_utc(systimestamp)")])
        elif s.bind.dialect.name == 'mysql':
            query = select([text("utc_timestamp()")])
        elif s.bind.dialect.name == 'sqlite':
            query = select([text("datetime('now', 'utc')")])
            storage_date_format = '%Y-%m-%d  %H:%M:%S'
        else:
            query = select([func.current_date()])

        for now, in s.execute(query):
            if storage_date_format:
                return datetime.strptime(now, storage_date_format)
            return now

    finally:
        s.remove()


def get_count(q):
    """
    Fast way to get count in SQLAlchemy
    Source: https://gist.github.com/hest/8798884
    Some limits, see a more thorough version above
    """

    count_q = q.statement.with_only_columns([func.count()]).order_by(None)
    count = q.session.execute(count_q).scalar()
    return count


def is_old_db():
    """
    Returns true, if alembic is used and the database is not on the
    same revision as the code base.
    """
    schema = config_get('database', 'schema', raise_exception=False)

    # checks if alembic is being used by looking up the AlembicVersion table
    if not get_engine().has_table(models.AlembicVersion.__tablename__, schema):
        return False

    s = get_session()
    query = s.query(models.AlembicVersion.version_num)
    return query.count() != 0 and str(query.first()[0]) != alembicrevision.ALEMBIC_REVISION


def json_implemented(session=None):
    """
    Checks if the database on the current server installation can support json fields.

    :param session: The active session of the database.
    :type session: Optional[Session]
    :returns: True, if json is supported, False otherwise.
    """
    if session is None:
        session = get_session()

    if session.bind.dialect.name == 'oracle':
        oracle_version = int(session.connection().connection.version.split('.')[0])
        if oracle_version < 12:
            return False
    elif session.bind.dialect.name == 'sqlite':
        return False

    return True


def try_drop_constraint(constraint_name, table_name):
    """
    Tries to drop the given constrained and returns successfully if the
    constraint already existed on Oracle databases.

    :param constraint_name: the constraint's name
    :param table_name: the table name where the constraint resides
    """
    try:
        op.drop_constraint(constraint_name, table_name)
    except DatabaseError as e:
        assert 'nonexistent constraint' in str(e)


def list_oracle_global_temp_tables(session):
    """
    Retrieve the list of global temporary tables in oracle
    """
    global_temp_tables = config_get_list('core', 'oracle_global_temp_tables', raise_exception=False, check_config_table=False, default='')
    if global_temp_tables:
        return [t.upper() for t in global_temp_tables]

    cache_key = 'oracle_global_temp_tables'
    # Set long expiration time to avoid hammering the database with this costly query
    global_temp_tables = REGION.get(cache_key, expiration_time=3600)
    if isinstance(global_temp_tables, NoValue):
        # As of time of writing, get_temp_table_names doesn't allow setting the correct schema when called
        # (like get_table_names allows). This may be fixed in a later version of sqlalchemy:
        # FIXME: substitute with something like this:
        # global_temp_tables = [t.upper() for t in inspect(session.bind).get_temp_table_names()]
        global_temp_tables = [
            str(t[0]).upper()
            for t in session.execute(
                text('SELECT UPPER(table_name) '
                     'FROM all_tables '
                     'WHERE OWNER = :owner AND IOT_NAME IS NULL AND DURATION IS NOT NULL'),
                dict(owner=models.BASE.metadata.schema.upper())
            )
        ]
        REGION.set(cache_key, global_temp_tables)
    return global_temp_tables


def _create_temp_table(name, *columns, primary_key=None, oracle_global_name=None, session=None, logger=logging.log):
    """
    Create a temporary table with the given columns, register it into a declarative base, and return it.

    Attention! calling this function while a table with the same `name` is being used will lead to
    bad consequences. Don't use it in recursive calls without taking special care.

    Declarative definition _requires_ a primary key. It should be a subset of '*columns' argument
    (either a single column, or a list). If not explicitly give, will use the first column as primary key.

    On oracle, there are 2 possible types of temporary tables: global/private.
    In the global case, tables are created once and then can be used by any session (with private data).
    Private tables are created on-the fly, but have many limitations. For example: no indexes allowed.
    This primary key is "fake" in this case, because it only exists in sqlalchemy and not in the database.

    Mysql and sqlite don't support automatic cleanup of temporary tables on commit. This means that a
    temporary table definition is preserved for the lifetime of a session. A session is regularly
    re-used by sqlalchemy, that's why we have to assume the required temporary table already exist and
    could contain data from a previous transaction. Drop all data from that table.
    """
    if not primary_key:
        primary_key = columns[0]
    if not hasattr(primary_key, '__iter__'):
        primary_key = (primary_key, )

    oracle_table_is_global = False
    if session.bind.dialect.name == 'oracle':
        # Retrieve the list of global temporary tables on oracle.
        # If the requested table is found to be global, re-use it,
        # otherwise create a private temporary table with random name
        global_temp_tables = list_oracle_global_temp_tables(session=session)
        if oracle_global_name is None:
            oracle_global_name = name
        if oracle_global_name.upper() in global_temp_tables:
            oracle_table_is_global = True
            additional_kwargs = {
                'oracle_on_commit': 'DELETE ROWS',
                'prefixes': ['GLOBAL TEMPORARY'],
            }
        else:
            logger(logging.WARNING, f"Global temporary table {name} doesn't exist. Using private temporary table.")
            additional_kwargs = {
                'oracle_on_commit': 'DROP DEFINITION',
                'prefixes': ['PRIVATE TEMPORARY'],
            }
            # PRIVATE_TEMP_TABLE_PREFIX, which defaults to "ORA$PTT_", _must_ prefix the name
            name = f"ORA$PTT_{name}"
            # Oracle doesn't support the if_not_exists construct, so add a random suffix to the
            # name to allow multiple calls to the same function within the same session.
            # For example: multiple attach_dids_to_dids(..., session=session)
            name = f'{name}_{generate_uuid()}'
    elif session.bind.dialect.name == 'postgresql':
        additional_kwargs = {
            'postgresql_on_commit': 'DROP',
            'prefixes': ['TEMPORARY'],
        }
    else:
        additional_kwargs = {
            'prefixes': ['TEMPORARY'],
        }

    base = declarative_base()
    table = Table(
        oracle_global_name if oracle_table_is_global else name,
        base.metadata,
        *columns,
        schema=models.BASE.metadata.schema if oracle_table_is_global else None,  # Temporary tables exist in a special schema, so a schema name cannot be given when creating a temporary table
        **additional_kwargs,
    )

    # Oracle private temporary tables don't support indexes.
    # So skip adding the constraints to the table in that case.
    if not session.bind.dialect.name == 'oracle' or oracle_table_is_global:
        table.append_constraint(PrimaryKeyConstraint(*primary_key))

    class DeclarativeObj(base):
        __table__ = table
        # The declarative base requires a primary key, even if it doesn't exist in the database.
        __mapper_args__ = {
            "primary_key": primary_key,
        }

    # Ensure the table exists and is empty.
    if session.bind.dialect.name == 'oracle':
        # Oracle doesn't support if_not_exists.
        # We ensured the unicity by appending a random string to the table name.
        if not oracle_table_is_global:
            session.execute(CreateTable(table))
    elif session.bind.dialect.name == 'postgresql':
        session.execute(CreateTable(table))
    else:
        # If it already exists, it can contain leftover data from a previous transaction
        # executed by sqlalchemy within the same session (which is being re-used now)
        # This is not the case for oracle and postgresql thanks to their "on_commit" support.
        session.execute(CreateTable(table, if_not_exists=True))
        session.query(DeclarativeObj).delete()
    return DeclarativeObj


class TempTableManager:
    """
    A class which manages temporary tables created during a session.

    Attempts to create multiple temporary tables with the same name during a session will
    result in creation of unique tables with an integer "index" suffix added to their name.
    Without this, there would be a risk that a temporary table containing needed data are
    cleaned up during a recursive function call, resulting in unexpected behavior.
    The recursive call may be indirect and hard to catch. For example:
    functionA -> functionB -> functionC -> functionA

    The lifecycle of this object is bound to a particular session. In rucio, we naver use
    sessions in multiple threads at a time, so no need to protect indexes with a mutex.
    """

    def __init__(self, session):
        self.session = session

        self.next_idx_to_use = {}

    def create_temp_table(self, name, *columns, primary_key=None, logger=logging.log):
        idx = self.next_idx_to_use.setdefault(name, 0)
        table = _create_temp_table(f'{name}_{idx}', *columns, primary_key=primary_key, session=self.session, logger=logger)
        self.next_idx_to_use[name] = idx + 1
        return table

    def create_scope_name_table(self, logger=logging.log):
        """
        Create a temporary table with columns 'scope' and 'name'
        """

        columns = [
            Column("scope", InternalScopeString(get_schema_value('SCOPE_LENGTH'))),
            Column("name", String(get_schema_value('NAME_LENGTH'))),
        ]
        return self.create_temp_table(
            'TEMPORARY_SCOPE_NAME',
            *columns,
            primary_key=columns,
            logger=logger,
        )

    def create_association_table(self, logger=logging.log):
        """
        Create a temporary table with columns 'scope', 'name', 'child_scope'and 'child_name'
        """

        columns = [
            Column("scope", InternalScopeString(get_schema_value('SCOPE_LENGTH'))),
            Column("name", String(get_schema_value('NAME_LENGTH'))),
            Column("child_scope", InternalScopeString(get_schema_value('SCOPE_LENGTH'))),
            Column("child_name", String(get_schema_value('NAME_LENGTH'))),
        ]
        return self.create_temp_table(
            'TEMPORARY_ASSOCIATION',
            *columns,
            primary_key=columns,
            logger=logger,
        )

    def create_id_table(self, logger=logging.log):
        """
        Create a temp table with a single id column of uuid type
        """

        return self.create_temp_table(
            'TEMPORARY_ID',
            Column("id", models.GUID()),
            logger=logger,
        )


def temp_table_mngr(session: "Session") -> TempTableManager:
    """
    Creates (if doesn't yet exist) and returns a TempTableManager instance associated to the session
    """
    key = 'temp_table_mngr'
    mngr = session.info.get(key)
    if not mngr:
        mngr = TempTableManager(session)
        session.info[key] = mngr
    return mngr
