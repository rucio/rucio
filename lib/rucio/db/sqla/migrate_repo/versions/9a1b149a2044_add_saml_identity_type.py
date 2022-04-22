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

''' add saml identity type '''

from alembic import context
from alembic.op import create_check_constraint, drop_constraint, execute

from rucio.db.sqla.util import try_drop_constraint

# Alembic revision identifiers
revision = '9a1b149a2044'
down_revision = '53b479c3cb0f'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''
    if context.get_context().dialect.name in ['oracle', 'postgresql']:
        try_drop_constraint('IDENTITIES_TYPE_CHK', 'identities')
        create_check_constraint(constraint_name='IDENTITIES_TYPE_CHK',
                                table_name='identities',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH', 'SAML')")
        try_drop_constraint('ACCOUNT_MAP_ID_TYPE_CHK', 'account_map')
        create_check_constraint(constraint_name='ACCOUNT_MAP_ID_TYPE_CHK',
                                table_name='account_map',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH', 'SAML')")

    elif context.get_context().dialect.name == 'mysql':
        execute('ALTER TABLE ' + schema + 'identities DROP CHECK IDENTITIES_TYPE_CHK')  # pylint: disable=no-member
        create_check_constraint(constraint_name='IDENTITIES_TYPE_CHK',
                                table_name='identities',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH', 'SAML')")
        execute('ALTER TABLE ' + schema + 'account_map DROP CHECK ACCOUNT_MAP_ID_TYPE_CHK')  # pylint: disable=no-member
        create_check_constraint(constraint_name='ACCOUNT_MAP_ID_TYPE_CHK',
                                table_name='account_map',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH', 'SAML')")


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''
    if context.get_context().dialect.name in ['oracle']:
        try_drop_constraint('IDENTITIES_TYPE_CHK', 'identities')
        create_check_constraint(constraint_name='IDENTITIES_TYPE_CHK',
                                table_name='identities',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH')")

        try_drop_constraint('ACCOUNT_MAP_ID_TYPE_CHK', 'account_map')
        create_check_constraint(constraint_name='ACCOUNT_MAP_ID_TYPE_CHK',
                                table_name='account_map',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH')")

    elif context.get_context().dialect.name == 'mysql':
        execute('ALTER TABLE ' + schema + 'identities DROP CHECK IDENTITIES_TYPE_CHK')  # pylint: disable=no-member
        create_check_constraint(constraint_name='IDENTITIES_TYPE_CHK',
                                table_name='identities',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH')")

        execute('ALTER TABLE ' + schema + 'account_map DROP CHECK ACCOUNT_MAP_ID_TYPE_CHK')  # pylint: disable=no-member
        create_check_constraint(constraint_name='ACCOUNT_MAP_ID_TYPE_CHK',
                                table_name='account_map',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH')")

    elif context.get_context().dialect.name == 'postgresql':

        drop_constraint('IDENTITIES_TYPE_CHK', 'identities', type_='check')
        create_check_constraint(constraint_name='IDENTITIES_TYPE_CHK',
                                table_name='identities',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH')")

        drop_constraint('ACCOUNT_MAP_ID_TYPE_CHK', 'account_map', type_='check')
        create_check_constraint(constraint_name='ACCOUNT_MAP_ID_TYPE_CHK',
                                table_name='account_map',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH')")
        # drop_constraint('ACCOUNT_MAP_ID_TYPE_FK', 'account_map', type_='foreignkey')
        # create_foreign_key('ACCOUNT_MAP_ID_TYPE_FK', 'account_map', 'identities', ['identity', 'identity_type'], ['identity', 'identity_type'])
