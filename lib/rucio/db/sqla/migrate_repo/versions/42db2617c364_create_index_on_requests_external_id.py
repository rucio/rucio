# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2014

"""create index on requests.external_id

Revision ID: 42db2617c364
Revises: 4bab9edd01fc
Create Date: 2015-03-23 11:56:44.690512

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = '42db2617c364'
down_revision = '4bab9edd01fc'


def upgrade():
    op.create_index('REQUESTS_EXTERNALID_UQ', 'requests', ['external_id'])


def downgrade():
    op.drop_index('REQUESTS_EXTERNALID_UQ', 'requests')
