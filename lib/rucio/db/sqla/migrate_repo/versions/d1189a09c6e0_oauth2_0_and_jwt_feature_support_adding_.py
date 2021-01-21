# -*- coding: utf-8 -*-
# Copyright 2019-2020 CERN
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
# - Jaroslav Guenther <jaroslav.guenther@cern.ch>, 2019-2020
# - Martin Barisits <martin.barisits@cern.ch>, 2020
# - Mario Lassnig <mario.lassnig@cern.ch>, 2020

''' OAuth2.0 and JWT feature support; adding table oauth_requests & several columns to tokens table '''

import datetime

import sqlalchemy as sa

from alembic import context
from alembic.op import (add_column, alter_column, drop_column,
                        create_table, create_primary_key, create_index,
                        create_check_constraint, drop_table, drop_constraint, execute)
from rucio.db.sqla.types import InternalAccountString

# Alembic revision identifiers
revision = 'd1189a09c6e0'
down_revision = '810a41685bc1'


def upgrade():
    '''
    Upgrade the database to this revision
    '''
    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''  # pylint: disable=no-member
    if context.get_context().dialect.name in ['oracle', 'postgresql']:  # pylint: disable=no-member
        drop_constraint('IDENTITIES_TYPE_CHK', 'identities', type_='check')
        create_check_constraint(constraint_name='IDENTITIES_TYPE_CHK',
                                table_name='identities',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH', 'SAML', 'OIDC')")
        drop_constraint('ACCOUNT_MAP_ID_TYPE_CHK', 'account_map', type_='check')
        create_check_constraint(constraint_name='ACCOUNT_MAP_ID_TYPE_CHK',
                                table_name='account_map',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH', 'SAML', 'OIDC')")
    elif context.get_context().dialect.name == 'mysql' and context.get_context().dialect.server_version_info[0] == 5:  # pylint: disable=no-member
        create_check_constraint(constraint_name='IDENTITIES_TYPE_CHK',
                                table_name='identities',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH', 'SAML', 'OIDC')")
        create_check_constraint(constraint_name='ACCOUNT_MAP_ID_TYPE_CHK',
                                table_name='account_map',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH', 'SAML', 'OIDC')")

    elif context.get_context().dialect.name == 'mysql' and context.get_context().dialect.server_version_info[0] == 8:  # pylint: disable=no-member
        execute('ALTER TABLE ' + schema + 'identities DROP CHECK IDENTITIES_TYPE_CHK')  # pylint: disable=no-member
        create_check_constraint(constraint_name='IDENTITIES_TYPE_CHK',
                                table_name='identities',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH', 'SAML', 'OIDC')")
        execute('ALTER TABLE ' + schema + 'account_map DROP CHECK ACCOUNT_MAP_ID_TYPE_CHK')  # pylint: disable=no-member
        create_check_constraint(constraint_name='ACCOUNT_MAP_ID_TYPE_CHK',
                                table_name='account_map',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH', 'SAML', 'OIDC')")

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:  # pylint: disable=no-member
        add_column('tokens', sa.Column('oidc_scope', sa.String(2048), nullable=True, default=None), schema=schema[:-1])
        add_column('tokens', sa.Column('audience', sa.String(315), nullable=True, default=None), schema=schema[:-1])
        add_column('tokens', sa.Column('refresh_token', sa.String(315), nullable=True, default=None), schema=schema[:-1])
        add_column('tokens', sa.Column('refresh', sa.Boolean(name='TOKENS_REFRESH_CHK'), default=False), schema=schema[:-1])
        add_column('tokens', sa.Column('refresh_start', sa.DateTime(), nullable=True, default=None), schema=schema[:-1])
        add_column('tokens', sa.Column('refresh_expired_at', sa.DateTime(), nullable=True, default=None), schema=schema[:-1])
        add_column('tokens', sa.Column('refresh_lifetime', sa.Integer(), nullable=True, default=None), schema=schema[:-1])

        create_table('oauth_requests',
                     sa.Column('account', InternalAccountString(25)),
                     sa.Column('state', sa.String(50)),
                     sa.Column('nonce', sa.String(50)),
                     sa.Column('access_msg', sa.String(2048)),
                     sa.Column('redirect_msg', sa.String(2048)),
                     sa.Column('refresh_lifetime', sa.Integer(), nullable=True),
                     sa.Column('ip', sa.String(39), nullable=True),
                     sa.Column('expired_at', sa.DateTime(), default=datetime.datetime.utcnow() + datetime.timedelta(seconds=600)),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))
        create_primary_key('OAUTH_REQUESTS_STATE_PK', 'oauth_requests', ['state'])
        create_check_constraint('OAUTH_REQUESTS_EXPIRED_AT_NN', 'oauth_requests', 'expired_at is not null')
        create_index('OAUTH_REQUESTS_ACC_EXP_AT_IDX', 'oauth_requests', ['account', 'expired_at'])
        create_index('OAUTH_REQUESTS_ACCESS_MSG_IDX', 'oauth_requests', ['access_msg'])

    if context.get_context().dialect.name in ['oracle', 'postgresql']:  # pylint: disable=no-member
        alter_column('tokens', 'token', existing_type=sa.String(length=352), type_=sa.String(length=3072), schema=schema[:-1])
    if context.get_context().dialect.name in ['mysql']:  # pylint: disable=no-member
        alter_column('tokens', 'token', existing_type=sa.String(length=352), type_=sa.String(length=3072), existing_nullable=False, nullable=False, schema=schema[:-1])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''
    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''  # pylint: disable=no-member
    if context.get_context().dialect.name in ['oracle']:  # pylint: disable=no-member
        drop_constraint('IDENTITIES_TYPE_CHK', 'identities', type_='check')
        create_check_constraint(constraint_name='IDENTITIES_TYPE_CHK',
                                table_name='identities',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH', 'SAML')")

        drop_constraint('ACCOUNT_MAP_ID_TYPE_CHK', 'account_map', type_='check')
        create_check_constraint(constraint_name='ACCOUNT_MAP_ID_TYPE_CHK',
                                table_name='account_map',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH', 'SAML')")
        drop_column('tokens', 'oidc_scope', schema=schema[:-1])
        drop_column('tokens', 'audience', schema=schema[:-1])
        drop_column('tokens', 'refresh_token', schema=schema[:-1])
        drop_column('tokens', 'refresh', schema=schema[:-1])
        drop_column('tokens', 'refresh_start', schema=schema[:-1])
        drop_column('tokens', 'refresh_expired_at', schema=schema[:-1])
        drop_column('tokens', 'refresh_lifetime', schema=schema[:-1])
        drop_table('oauth_requests')
        alter_column('tokens', 'token', existing_type=sa.String(length=3072), type_=sa.String(length=352), schema=schema[:-1])

    elif context.get_context().dialect.name == 'mysql' and context.get_context().dialect.server_version_info[0] == 5:  # pylint: disable=no-member
        create_check_constraint(constraint_name='IDENTITIES_TYPE_CHK',
                                table_name='identities',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH', 'SAML')")

        create_check_constraint(constraint_name='ACCOUNT_MAP_ID_TYPE_CHK',
                                table_name='account_map',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH', 'SAML')")
        drop_column('tokens', 'oidc_scope', schema=schema[:-1])
        drop_column('tokens', 'audience', schema=schema[:-1])
        drop_column('tokens', 'refresh_token', schema=schema[:-1])
        drop_column('tokens', 'refresh', schema=schema[:-1])
        drop_column('tokens', 'refresh_start', schema=schema[:-1])
        drop_column('tokens', 'refresh_expired_at', schema=schema[:-1])
        drop_column('tokens', 'refresh_lifetime', schema=schema[:-1])
        alter_column('tokens', 'token', existing_type=sa.String(length=3072), type_=sa.String(length=352), existing_nullable=False, nullable=False, schema=schema[:-1])
        drop_table('oauth_requests')

    elif context.get_context().dialect.name == 'mysql' and context.get_context().dialect.server_version_info[0] == 8:  # pylint: disable=no-member
        create_check_constraint(constraint_name='IDENTITIES_TYPE_CHK',
                                table_name='identities',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH', 'SAML')")

        create_check_constraint(constraint_name='ACCOUNT_MAP_ID_TYPE_CHK',
                                table_name='account_map',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH', 'SAML')")
        drop_column('tokens', 'oidc_scope', schema=schema[:-1])
        drop_column('tokens', 'audience', schema=schema[:-1])
        drop_column('tokens', 'refresh_token', schema=schema[:-1])
        drop_column('tokens', 'refresh', schema=schema[:-1])
        drop_column('tokens', 'refresh_start', schema=schema[:-1])
        drop_column('tokens', 'refresh_expired_at', schema=schema[:-1])
        drop_column('tokens', 'refresh_lifetime', schema=schema[:-1])
        alter_column('tokens', 'token', existing_type=sa.String(length=3072), type_=sa.String(length=352), existing_nullable=False, nullable=False, schema=schema[:-1])
        drop_table('oauth_requests')

    elif context.get_context().dialect.name == 'postgresql':  # pylint: disable=no-member

        create_check_constraint(constraint_name='IDENTITIES_TYPE_CHK',
                                table_name='identities',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH', 'SAML')")

        create_check_constraint(constraint_name='ACCOUNT_MAP_ID_TYPE_CHK',
                                table_name='account_map',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH', 'SAML')")
        drop_column('tokens', 'oidc_scope', schema=schema[:-1])
        drop_column('tokens', 'audience', schema=schema[:-1])
        drop_column('tokens', 'refresh_token', schema=schema[:-1])
        drop_column('tokens', 'refresh', schema=schema[:-1])
        drop_column('tokens', 'refresh_start', schema=schema[:-1])
        drop_column('tokens', 'refresh_expired_at', schema=schema[:-1])
        drop_column('tokens', 'refresh_lifetime', schema=schema[:-1])
        alter_column('tokens', 'token', existing_type=sa.String(length=3072), type_=sa.String(length=352), schema=schema[:-1])
        drop_table('oauth_requests')
