#!/usr/bin/env python
# Copyright 2020 CERN for the benefit of the ATLAS collaboration.
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
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Gabriele Gaetano Fronze' <gabriele.fronze@to.infn.it>, 2020

import sys
import os.path
base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_path)
os.chdir(base_path)

import argparse  # noqa: E402
from datetime import datetime  # noqa: E402
from traceback import format_exc  # noqa: E402

from sqlalchemy import func  # noqa: E402
from sqlalchemy.engine import reflection  # noqa: E402
from sqlalchemy.schema import AddConstraint, DropConstraint, ForeignKeyConstraint, MetaData, Table  # noqa: E402
from sqlalchemy.sql import bindparam  # noqa: E402
from sqlalchemy.sql.expression import cast  # noqa: E402
from sqlalchemy.types import CHAR  # noqa: E402

from rucio.common.config import config_get_bool  # noqa: E402
from rucio.common.types import InternalAccount  # noqa: E402
from rucio.core.account import del_account  # noqa: E402
from rucio.core.vo import list_vos  # noqa: E402
from rucio.db.sqla import session  # noqa: E402
from rucio.db.sqla.util import create_root_account  # noqa: E402


def split_vo(dialect, column, return_vo=False):
    """
    Utility script for extracting the name and VO from InternalAccount/Scope entries in the DB.

    :param dialect:   The dialct of the DB.
    :param column:    The column to perform the operation on.
    :param return_vo: If True, return the 3 characters after the '@' symbol, else return everything before it.
    """
    if dialect == 'postgresql':
        if return_vo:
            return func.split_part(column, bindparam('split_character'), bindparam('int_2'))
        else:
            return func.split_part(column, bindparam('split_character'), bindparam('int_1'))
    else:
        # Dialects other than postgresql haven't been tested
        i = func.INSTR(column, bindparam('split_character'))
        if return_vo:
            return func.SUBSTR(column, i + 1)
        else:
            return func.SUBSTR(column, bindparam('int_1'), i - 1)


def rename_vo(old_vo, new_vo, insert_new_vo=False, description=None, email=None, commit_changes=False, skip_history=False, echo=True):
    """
    Updates rows so that entries associated with `old_vo` are now associated with `new_vo` as part of multi-VO migration.

    :param old_vo:         The 3 character string for the current VO (for a single-VO instance this will be 'def').
    :param new_vo:         The 3 character string for the new VO.
    :param insert_new_vo:  If True then an entry for `new_vo` is created in the database.
    :param description:    Full description of the new VO, unused if `insert_new_vo` is False.
    :param email:          Admin email for the new VO, unused if `insert_new_vo` is False.
    :param commit_changes: If True then changes are made against the database directly.
                           If False, then nothing is commited and the commands needed are dumped to be run later.
    :param skip_history:   If True then tables without FKC containing historical data will not be converted to save time.
    """
    success = True
    engine = session.get_engine(echo=echo)
    conn = engine.connect()
    trans = conn.begin()
    inspector = reflection.Inspector.from_engine(engine)
    metadata = MetaData(bind=conn, reflect=True)
    dialect = engine.dialect.name

    # Gather all the columns that need updating and all relevant foreign key constraints
    all_fks = []
    tables_and_columns = []
    for table_name in inspector.get_table_names():
        if skip_history and ('_history' in table_name or '_hist_recent' in table_name):
            continue
        fks = []
        table = Table(table_name, metadata)
        for column in table.c:
            if 'scope' in column.name or column.name == 'account':
                tables_and_columns.append((table, column))
        for fk in inspector.get_foreign_keys(table_name):
            if not fk['name']:
                continue
            if 'scope' in fk['referred_columns'] or 'account' in fk['referred_columns']:
                fks.append(ForeignKeyConstraint(fk['constrained_columns'], [fk['referred_table'] + '.' + r for r in fk['referred_columns']],
                                                name=fk['name'], table=table, **fk['options']))
        all_fks.extend(fks)

    try:
        bound_params = {'old_vo': old_vo,
                        'new_vo': new_vo,
                        'old_vo_suffix': '' if old_vo == 'def' else old_vo,
                        'new_vo_suffix': '' if new_vo == 'def' else '@%s' % new_vo,
                        'split_character': '@',
                        'int_1': 1,
                        'int_2': 2,
                        'new_description': description,
                        'new_email': email,
                        'datetime': datetime.utcnow()}

        bound_params_text = {}
        for key in bound_params:
            if isinstance(bound_params[key], int):
                bound_params_text[key] = bound_params[key]
            else:
                bound_params_text[key] = "'%s'" % bound_params[key]

        if insert_new_vo:
            table = Table('vos', metadata)
            insert_command = table.insert().values(vo=bindparam('new_vo'),
                                                   description=bindparam('new_description'),
                                                   email=bindparam('new_email'),
                                                   updated_at=bindparam('datetime'),
                                                   created_at=bindparam('datetime'))
            print(str(insert_command) % bound_params_text + ';')
            if commit_changes:
                conn.execute(insert_command, bound_params)

        # Drop all FKCs affecting InternalAccounts/Scopes
        for fk in all_fks:
            print(str(DropConstraint(fk)) + ';')
            if commit_changes:
                conn.execute(DropConstraint(fk))

        # Update columns
        for table, column in tables_and_columns:
            update_command = table.update().where(split_vo(dialect, column, return_vo=True) == bindparam('old_vo_suffix'))

            if new_vo == 'def':
                update_command = update_command.values({column.name: split_vo(dialect, column)})
            else:
                update_command = update_command.values({column.name: split_vo(dialect, column) + cast(bindparam('new_vo_suffix'), CHAR(4))})

            print(str(update_command) % bound_params_text + ';')
            if commit_changes:
                conn.execute(update_command, bound_params)

        table = Table('rses', metadata)
        update_command = table.update().where(table.c.vo == bindparam('old_vo')).values(vo=bindparam('new_vo'))
        print(str(update_command) % bound_params_text + ';')
        if commit_changes:
            conn.execute(update_command, bound_params)

        # Re-add the FKCs we dropped
        for fkc in all_fks:
            print(str(AddConstraint(fkc)) + ';')
            if commit_changes:
                conn.execute(AddConstraint(fkc))
    except:
        success = False
        print(format_exc())
        print('Exception occured, changes not committed to DB.')

    if commit_changes and success:
        trans.commit()
    trans.close()
    return success


def remove_vo(vo, commit_changes=False, skip_history=False, echo=True):
    """
    Deletes rows associated with `vo` as part of multi-VO migration.

    :param vo:             The 3 character string for the VO being removed from the DB.
    :param commit_changes: If True then changes are made against the database directly.
                           If False, then nothing is commited and the commands needed are dumped to be run later.
    :param skip_history:   If True then tables without FKC containing historical data will not be converted to save time.
    """
    success = True
    engine = session.get_engine(echo=echo)
    conn = engine.connect()
    trans = conn.begin()
    inspector = reflection.Inspector.from_engine(engine)
    metadata = MetaData(bind=conn, reflect=True)
    dialect = engine.dialect.name

    # Gather all the columns that need deleting and all relevant foreign key constraints
    all_fks = []
    tables_and_columns = []
    tables_and_columns_rse = []
    for table_name in inspector.get_table_names():
        if skip_history and ('_history' in table_name or '_hist_recent' in table_name):
            continue
        fks = []
        table = Table(table_name, metadata)
        for column in table.c:
            if 'scope' in column.name or column.name == 'account':
                tables_and_columns.append((table, column))
            if 'rse_id' in column.name:
                tables_and_columns_rse.append((table, column))
        for fk in inspector.get_foreign_keys(table_name):
            if not fk['name']:
                continue
            if 'scope' in fk['referred_columns'] or 'account' in fk['referred_columns'] or ('rse' in fk['referred_table'] and 'id' in fk['referred_columns']):
                fks.append(ForeignKeyConstraint(fk['constrained_columns'], [fk['referred_table'] + '.' + r for r in fk['referred_columns']],
                                                name=fk['name'], table=table, **fk['options']))
        all_fks.extend(fks)

    try:
        bound_params = {'vo': vo,
                        'vo_suffix': '' if vo == 'def' else vo,
                        'split_character': '@',
                        'int_1': 1,
                        'int_2': 2}

        bound_params_text = {}
        for key in bound_params:
            if isinstance(bound_params[key], int):
                bound_params_text[key] = bound_params[key]
            else:
                bound_params_text[key] = "'%s'" % bound_params[key]

        # Drop all FKCs affecting InternalAccounts/Scopes or RSE IDs
        for fk in all_fks:
            print(str(DropConstraint(fk)) + ';')
            if commit_changes:
                conn.execute(DropConstraint(fk))

        # Delete rows
        for table, column in tables_and_columns:
            delete_command = table.delete().where(split_vo(dialect, column, return_vo=True) == bindparam('vo_suffix'))
            print(str(delete_command) % bound_params_text + ';')
            if commit_changes:
                conn.execute(delete_command, bound_params)

        rse_table = Table('rses', metadata)
        for table, column in tables_and_columns_rse:
            delete_command = table.delete().where(column == rse_table.c.id).where(rse_table.c.vo == bindparam('vo'))
            print(str(delete_command) % bound_params_text + ';')
            if commit_changes:
                conn.execute(delete_command, bound_params)

        delete_command = rse_table.delete().where(rse_table.c.vo == bindparam('vo'))
        print(str(delete_command) % bound_params_text + ';')
        if commit_changes:
            conn.execute(delete_command, bound_params)

        table = Table('vos', metadata)
        delete_command = table.delete().where(table.c.vo == bindparam('vo'))
        print(str(delete_command) % bound_params_text + ';')
        if commit_changes:
            conn.execute(delete_command, bound_params)

        # Re-add the FKCs we dropped
        for fkc in all_fks:
            print(str(AddConstraint(fkc)) + ';')
            if commit_changes:
                conn.execute(AddConstraint(fkc))
    except:
        success = False
        print(format_exc())
        print('Exception occured, changes not committed to DB.')

    if commit_changes and success:
        trans.commit()
    trans.close()
    return success


def convert_to_mvo(new_vo, description, email, create_super_root=False, commit_changes=False, skip_history=False, echo=True):
    """
    Converts a single-VO database to a multi-VO one with the specified VO details.

    :param new_vo:            The 3 character string for the new VO.
    :param description:       Full description of the new VO.
    :param email:             Admin email for the new VO.
    :param create_super_root: If True and the renaming was successful, then create a super_root account at VO def.
    :param commit_changes:    If True then changes are made against the database directly.
                              If False, then nothing is commited and the commands needed are dumped to be run later.
    :param skip_history:      If True then tables without FKC containing historical data will not be converted to save time.
    """
    if not config_get_bool('common', 'multi_vo', False, False):
        print('Multi-VO mode is not enabled in the config file, aborting conversion.')
        return

    s = session.get_session()
    vos = [vo['vo'] for vo in list_vos(session=s)]
    if new_vo not in vos:
        insert_new_vo = True
    else:
        insert_new_vo = False

    success = rename_vo('def', new_vo, insert_new_vo=insert_new_vo, description=description, email=email,
                        commit_changes=commit_changes, skip_history=skip_history, echo=echo)
    if create_super_root and success:
        create_root_account(create_counters=False)
    s.close()


def convert_to_svo(old_vo, delete_vos=False, commit_changes=False, skip_history=False, echo=True):
    """
    Converts a multi-VO database to a single-VO one by renaming the given VO and (optionally) deleting entries for other VOs and the super_root.
    Intended to be run on a copy of the original database that contains several VOs.

    :param old_vo:         The 3 character string for the old VO.
    :param delete_vos:     If True then all entries associated with a VO other than `old_vo` will be deleted.
    :param commit_changes: If True then changes are made against the database directly and the old super_root account will be (soft) deleted.
                           If False, then nothing is commited and the commands needed are dumped to be run later.
    :param skip_history:   If True then tables without FKC containing historical data will not be converted to save time.
    """
    if not config_get_bool('common', 'multi_vo', False, False):
        print('Multi-VO mode is not enabled in the config file, aborting conversion.')
        return

    rename_vo(old_vo, 'def', commit_changes=commit_changes, skip_history=skip_history, echo=echo)
    s = session.get_session()
    if delete_vos:
        success_all = True
        for vo in list_vos(session=s):
            if vo['vo'] != 'def':
                success = remove_vo(vo['vo'], commit_changes=commit_changes, skip_history=skip_history, echo=echo)
                success_all = success_all and success
        if commit_changes and success_all:
            del_account(InternalAccount('super_root', vo='def'), session=s)
    s.close()


def main():
    """
    Parses the arguments and determines which operation to call.
    """
    parser = argparse.ArgumentParser(description='Utility script for associating database entries with a different VO in order to convert an instance to/from multi-VO mode.')
    parser.add_argument('--commit_changes', '-cc', action='store_true',
                        help='Attempts to commit changes to the database. If not provided then the SQL commands printed need to be run manually along with account creation/deletion.')
    parser.add_argument('--skip_history', '-sh', action='store_true', help='Skips the potentially large historical tables to speed up the operation.')
    subparsers = parser.add_subparsers(title='operation', description='The operation to perform on the database.')

    parser_mvo = subparsers.add_parser('convert_to_mvo', help='Associates all entries in an existing s-VO database with the VO provided, making the database m-VO compatible.')
    parser_mvo.add_argument('new_vo', help='Three character string to identify the new VO. Will be added to the database if it doesn\'t already exist.')
    parser_mvo.add_argument('description', help='Full description of the VO to be used.')
    parser_mvo.add_argument('email', help='Admin email for the new VO.')
    parser_mvo.add_argument('--create_super_root', '-csr', action='store_true', help='If specified a super_root account is added to VO def.')

    parser_svo = subparsers.add_parser('convert_to_svo', help='Entries associated with the VO provided have this association removed, making the database s-VO compatible.')
    parser_svo.add_argument('old_vo', help='Three character string to identify the old VO. Data associated with this VO will be converted.')
    parser_svo.add_argument('--delete_vos', '-dv', action='store_true', help='If specified any data not associated with `old_vo` will be deleted from the database.')

    args = parser.parse_args()
    if 'new_vo' in args:
        convert_to_mvo(**vars(args))
    if 'old_vo' in args:
        convert_to_svo(**vars(args))


if __name__ == '__main__':
    main()
