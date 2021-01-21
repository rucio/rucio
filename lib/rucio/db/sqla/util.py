# -*- coding: utf-8 -*-
# Copyright 2015-2021 CERN
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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2015-2016
# - Martin Barisits <martin.barisits@cern.ch>, 2017-2019
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018-2019
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Ruturaj Gujar <ruturaj.gujar23@gmail.com>, 2019
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Eric Vaandering <ewv@fnal.gov>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021

from __future__ import print_function

from datetime import datetime
from hashlib import sha256
from os import urandom
from traceback import format_exc
from typing import TYPE_CHECKING

from alembic import command
from alembic.config import Config
from sqlalchemy import func
from sqlalchemy.engine import reflection
from sqlalchemy.exc import IntegrityError
from sqlalchemy.schema import CreateSchema, MetaData, Table, DropTable, ForeignKeyConstraint, DropConstraint
from sqlalchemy.sql.expression import select, text

from rucio import alembicrevision
from rucio.common.config import config_get
from rucio.common.types import InternalAccount
from rucio.core.account_counter import create_counters_for_new_account
from rucio.db.sqla import models
from rucio.db.sqla.constants import AccountStatus, AccountType, IdentityType
from rucio.db.sqla.session import get_engine, get_session, get_dump_engine

if TYPE_CHECKING:
    from typing import Optional  # noqa: F401
    from sqlalchemy.orm import Session  # noqa: F401


def build_database(echo=True):
    """ Applies the schema to the database. Run this command once to build the database. """
    engine = get_engine(echo=echo)

    schema = config_get('database', 'schema', raise_exception=False)
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


def destroy_database(echo=True):
    """ Removes the schema from the database. Only useful for test cases or malicious intents. """
    engine = get_engine(echo=echo)

    try:
        models.unregister_models(engine)
    except Exception as e:
        print('Cannot destroy schema -- assuming already gone, continuing:', e)


def drop_everything(echo=True):
    """ Pre-gather all named constraints and table names, and drop everything. This is better than using metadata.reflect();
        metadata.drop_all() as it handles cyclical constraints between tables.
        Ref. http://www.sqlalchemy.org/trac/wiki/UsageRecipes/DropEverything
    """
    engine = get_engine(echo=echo)
    conn = engine.connect()

    # the transaction only applies if the DB supports
    # transactional DDL, i.e. Postgresql, MS SQL Server
    trans = conn.begin()

    inspector = reflection.Inspector.from_engine(engine)

    # gather all data first before dropping anything.
    # some DBs lock after things have been dropped in
    # a transaction.
    metadata = MetaData()

    tbs = []
    all_fks = []

    for table_name in inspector.get_table_names():
        fks = []
        for fk in inspector.get_foreign_keys(table_name):
            if not fk['name']:
                continue
            fks.append(ForeignKeyConstraint((), (), name=fk['name']))
        t = Table(table_name, metadata, *fks)
        tbs.append(t)
        all_fks.extend(fks)

    for fkc in all_fks:
        try:
            print(str(DropConstraint(fkc)) + ';')
            conn.execute(DropConstraint(fkc))
        except:
            print(format_exc())

    for table in tbs:
        try:
            print(str(DropTable(table)).strip() + ';')
            conn.execute(DropTable(table))
        except:
            print(format_exc())

    trans.commit()


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
