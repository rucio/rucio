# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2014

"""added columns to table requests

Revision ID: a616581ee47
Revises: 2854cd9e168
Create Date: 2014-07-10 14:02:53.757564

"""

import sqlalchemy as sa

from alembic import context, op
from sqlalchemy import BigInteger

from rucio.db.sqla.models import String

# revision identifiers, used by Alembic.
revision = 'a616581ee47'
down_revision = '2854cd9e168'


def upgrade():
    op.add_column('requests', sa.Column('bytes', BigInteger))
    op.add_column('requests', sa.Column('md5', String(32)))
    op.add_column('requests', sa.Column('adler32', String(8)))
    op.add_column('requests', sa.Column('dest_url', String(2048)))
    op.add_column('requests_history', sa.Column('bytes', BigInteger))
    op.add_column('requests_history', sa.Column('md5', String(32)))
    op.add_column('requests_history', sa.Column('adler32', String(8)))
    op.add_column('requests_history', sa.Column('dest_url', String(2048)))


def downgrade():
    if context.get_context().dialect.name != 'sqlite':
        op.drop_column('requests', 'bytes')
        op.drop_column('requests', 'md5')
        op.drop_column('requests', 'adler32')
        op.drop_column('requests', 'dest_url')
        op.drop_column('requests_history', 'bytes')
        op.drop_column('requests_history', 'md5')
        op.drop_column('requests_history', 'adler32')
        op.drop_column('requests_history', 'dest_url')
