# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2014
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2015


"""Adding transient metadata

Revision ID: 4cf0a2e127d4
Revises: 271a46ea6244
Create Date: 2015-01-16 16:42:37.039637

"""

from alembic import op, context
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '4cf0a2e127d4'
down_revision = '271a46ea6244'


def upgrade():
    if context.get_context().dialect.name not in ('sqlite'):
        op.add_column('dids', sa.Column('transient', sa.Boolean(name='DID_TRANSIENT_CHK'), server_default='0'))


def downgrade():
    if context.get_context().dialect.name not in ('sqlite'):
        op.drop_column('dids', 'transient')
