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

""" OAuth2.0 and JWT feature support; adding table oauth_requests & several columns to tokens table """

import datetime

import sqlalchemy as sa
from alembic.op import create_index, create_primary_key, create_table, drop_column, drop_table, execute

from rucio.db.sqla.migrate_repo import add_column, alter_column, create_check_constraint, get_effective_schema, is_current_dialect, qualify_table
from rucio.db.sqla.types import InternalAccountString
from rucio.db.sqla.util import try_drop_constraint

# Alembic revision identifiers
revision = 'd1189a09c6e0'
down_revision = '810a41685bc1'


def upgrade():
    """
    Upgrade the database to this revision
    """
    schema = get_effective_schema()
    account_map_table = qualify_table('account_map')
    identities_table = qualify_table('identities')
    if is_current_dialect('oracle', 'postgresql'):
        try_drop_constraint('IDENTITIES_TYPE_CHK', 'identities')
        create_check_constraint(constraint_name='IDENTITIES_TYPE_CHK',
                                table_name='identities',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH', 'SAML', 'OIDC')")
        try_drop_constraint('ACCOUNT_MAP_ID_TYPE_CHK', 'account_map')
        create_check_constraint(constraint_name='ACCOUNT_MAP_ID_TYPE_CHK',
                                table_name='account_map',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH', 'SAML', 'OIDC')")
    elif is_current_dialect('mysql'):
        execute(
            f"""
            ALTER TABLE {identities_table}
            DROP CHECK IDENTITIES_TYPE_CHK
            """
        )
        create_check_constraint(constraint_name='IDENTITIES_TYPE_CHK',
                                table_name='identities',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH', 'SAML', 'OIDC')")
        execute(
            f"""
            ALTER TABLE {account_map_table}
            DROP CHECK ACCOUNT_MAP_ID_TYPE_CHK
            """
        )
        create_check_constraint(constraint_name='ACCOUNT_MAP_ID_TYPE_CHK',
                                table_name='account_map',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH', 'SAML', 'OIDC')")

    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        add_column('tokens', sa.Column('oidc_scope', sa.String(2048), nullable=True, default=None))
        add_column('tokens', sa.Column('audience', sa.String(315), nullable=True, default=None))
        add_column('tokens', sa.Column('refresh_token', sa.String(315), nullable=True, default=None))
        add_column('tokens', sa.Column('refresh', sa.Boolean(name='TOKENS_REFRESH_CHK', create_constraint=True), default=False))
        add_column('tokens', sa.Column('refresh_start', sa.DateTime(), nullable=True, default=None))
        add_column('tokens', sa.Column('refresh_expired_at', sa.DateTime(), nullable=True, default=None))
        add_column('tokens', sa.Column('refresh_lifetime', sa.Integer(), nullable=True, default=None))

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
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow),
                     schema=schema)
        create_primary_key('OAUTH_REQUESTS_STATE_PK', 'oauth_requests', ['state'], schema=schema)
        create_check_constraint('OAUTH_REQUESTS_EXPIRED_AT_NN', 'oauth_requests', 'expired_at is not null')
        create_index('OAUTH_REQUESTS_ACC_EXP_AT_IDX', 'oauth_requests', ['account', 'expired_at'], schema=schema)
        create_index('OAUTH_REQUESTS_ACCESS_MSG_IDX', 'oauth_requests', ['access_msg'], schema=schema)

    if is_current_dialect('oracle', 'postgresql'):
        alter_column('tokens', 'token', existing_type=sa.String(length=352), type_=sa.String(length=3072))
    if is_current_dialect('mysql'):
        alter_column('tokens', 'token', existing_type=sa.String(length=352), type_=sa.String(length=3072), existing_nullable=False, nullable=False)


def downgrade():
    """
    Downgrade the database to the previous revision
    """
    schema = get_effective_schema()
    if is_current_dialect('oracle'):
        try_drop_constraint('IDENTITIES_TYPE_CHK', 'identities')
        create_check_constraint(constraint_name='IDENTITIES_TYPE_CHK',
                                table_name='identities',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH', 'SAML')")

        try_drop_constraint('ACCOUNT_MAP_ID_TYPE_CHK', 'account_map')
        create_check_constraint(constraint_name='ACCOUNT_MAP_ID_TYPE_CHK',
                                table_name='account_map',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH', 'SAML')")
        drop_column('tokens', 'oidc_scope', schema=schema)
        drop_column('tokens', 'audience', schema=schema)
        drop_column('tokens', 'refresh_token', schema=schema)
        drop_column('tokens', 'refresh', schema=schema)
        drop_column('tokens', 'refresh_start', schema=schema)
        drop_column('tokens', 'refresh_expired_at', schema=schema)
        drop_column('tokens', 'refresh_lifetime', schema=schema)
        drop_table('oauth_requests', schema=schema)
        alter_column('tokens', 'token', existing_type=sa.String(length=3072), type_=sa.String(length=352))

    elif is_current_dialect('mysql'):
        create_check_constraint(constraint_name='IDENTITIES_TYPE_CHK',
                                table_name='identities',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH', 'SAML')")

        create_check_constraint(constraint_name='ACCOUNT_MAP_ID_TYPE_CHK',
                                table_name='account_map',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH', 'SAML')")
        drop_column('tokens', 'oidc_scope', schema=schema)
        drop_column('tokens', 'audience', schema=schema)
        drop_column('tokens', 'refresh_token', schema=schema)
        drop_column('tokens', 'refresh', schema=schema)
        drop_column('tokens', 'refresh_start', schema=schema)
        drop_column('tokens', 'refresh_expired_at', schema=schema)
        drop_column('tokens', 'refresh_lifetime', schema=schema)
        alter_column('tokens', 'token', existing_type=sa.String(length=3072), type_=sa.String(length=352), existing_nullable=False, nullable=False)
        drop_table('oauth_requests', schema=schema)

    elif is_current_dialect('postgresql'):

        create_check_constraint(constraint_name='IDENTITIES_TYPE_CHK',
                                table_name='identities',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH', 'SAML')")

        create_check_constraint(constraint_name='ACCOUNT_MAP_ID_TYPE_CHK',
                                table_name='account_map',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH', 'SAML')")
        drop_column('tokens', 'oidc_scope', schema=schema)
        drop_column('tokens', 'audience', schema=schema)
        drop_column('tokens', 'refresh_token', schema=schema)
        drop_column('tokens', 'refresh', schema=schema)
        drop_column('tokens', 'refresh_start', schema=schema)
        drop_column('tokens', 'refresh_expired_at', schema=schema)
        drop_column('tokens', 'refresh_lifetime', schema=schema)
        alter_column('tokens', 'token', existing_type=sa.String(length=3072), type_=sa.String(length=352))
        drop_table('oauth_requests', schema=schema)
