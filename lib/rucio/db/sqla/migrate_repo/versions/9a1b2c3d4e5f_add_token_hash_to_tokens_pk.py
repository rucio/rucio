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

"""add token_hash to tokens pk"""    # noqa: D400, D415

import sqlalchemy as sa
from alembic import context, op

# Alembic revision identifiers
revision = '9a1b2c3d4e5f'
down_revision = '1bd076539b6e'

TOKEN_HASH_LENGTH = 64
BATCH_SIZE = 10000


def _backfill_token_hash(tokens: sa.Table) -> None:
    """
    Compute the hash of every existing token, in Python rather than in SQL
    because SHA-256 is spelled differently by each backend.
    """
    from rucio.common.utils import token_hash

    connection = op.get_bind()
    while True:
        rows = connection.execute(
            sa.select(tokens.c.token)
            .where(tokens.c.token_hash.is_(None))
            .limit(BATCH_SIZE)
        ).scalars().all()
        if not rows:
            break
        connection.execute(
            tokens.update()
            .where(tokens.c.token == sa.bindparam('_token'))
            .values(token_hash=sa.bindparam('_token_hash')),
            [{'_token': token, '_token_hash': token_hash(token)} for token in rows],
        )


def _drop_duplicate_tokens(tokens: sa.Table) -> None:
    """
    Keep only the oldest row per token, as the restored primary key requires.

    Selected and deleted separately because MySQL refuses a subquery over the
    table a DELETE targets.
    """
    connection = op.get_bind()
    duplicated = connection.execute(
        sa.select(tokens.c.token_hash)
        .group_by(tokens.c.token_hash)
        .having(sa.func.count() > 1)
    ).scalars().all()

    for token_hash_value in duplicated:
        accounts = connection.execute(
            sa.select(tokens.c.account)
            .where(tokens.c.token_hash == token_hash_value)
            .order_by(tokens.c.created_at)
        ).scalars().all()
        connection.execute(
            tokens.delete().where(
                tokens.c.token_hash == token_hash_value,
                tokens.c.account.in_(accounts[1:]),
            )
        )


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''

        op.add_column('tokens', sa.Column('token_hash', sa.String(TOKEN_HASH_LENGTH)), schema=schema)

        tokens = sa.Table(
            'tokens', sa.MetaData(),
            sa.Column('token', sa.String(3072)),
            sa.Column('token_hash', sa.String(TOKEN_HASH_LENGTH)),
            schema=schema or None,
        )
        _backfill_token_hash(tokens)

        op.drop_constraint('TOKENS_ACCOUNT_FK', 'tokens', type_='foreignkey', schema=schema)
        op.drop_constraint('TOKENS_PK', 'tokens', type_='primary', schema=schema)
        op.alter_column('tokens', 'token_hash', existing_type=sa.String(TOKEN_HASH_LENGTH),
                        nullable=False, schema=schema)
        op.create_primary_key('TOKENS_PK', 'tokens', ['token_hash', 'account'], schema=schema)
        op.create_foreign_key('TOKENS_ACCOUNT_FK', 'tokens', 'accounts', ['account'], ['account'],
                              source_schema=schema, referent_schema=schema)


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''

        tokens = sa.Table(
            'tokens', sa.MetaData(),
            sa.Column('token', sa.String(3072)),
            sa.Column('token_hash', sa.String(TOKEN_HASH_LENGTH)),
            sa.Column('account', sa.String(25)),
            sa.Column('created_at', sa.DateTime),
            schema=schema or None,
        )
        _drop_duplicate_tokens(tokens)

        op.drop_constraint('TOKENS_ACCOUNT_FK', 'tokens', type_='foreignkey', schema=schema)
        op.drop_constraint('TOKENS_PK', 'tokens', type_='primary', schema=schema)
        op.create_primary_key('TOKENS_PK', 'tokens', ['token'], schema=schema)
        op.create_foreign_key('TOKENS_ACCOUNT_FK', 'tokens', 'accounts', ['account'], ['account'],
                              source_schema=schema, referent_schema=schema)
        op.drop_column('tokens', 'token_hash', schema=schema)
