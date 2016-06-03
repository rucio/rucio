# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Wen Guan, <wen.guan@cern.ch>, 2015

"""create index on requests.rule_id

Revision ID: 4bab9edd01fc
Revises: ae2a56fcc89
Create Date: 2015-03-20 15:58:02.456873

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = '4bab9edd01fc'
down_revision = 'ae2a56fcc89'


def upgrade():
    op.create_index('REQUESTS_RULEID_IDX', 'requests', ['rule_id'])


def downgrade():
    op.drop_index('REQUESTS_RULEID_IDX', 'requests')
