# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Wen Guan, <wen.guan@cern.ch>, 2015

"""update REQUESTS_TYP_STA_UPD_IDX index

Revision ID: 44278720f774
Revises: 40ad39ce3160
Create Date: 2015-05-06 16:37:06.805315

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = '44278720f774'
down_revision = '40ad39ce3160'


def upgrade():
    op.drop_index('REQUESTS_TYP_STA_UPD_IDX', 'requests')
    op.create_index('REQUESTS_TYP_STA_UPD_IDX', 'requests', ['request_type', 'state', 'activity'])
    op.create_index('REQUESTS_TYP_STA_UPD_IDX_OLD', 'requests', ['request_type', 'state', 'updated_at'])


def downgrade():
    op.drop_index('REQUESTS_TYP_STA_UPD_IDX', 'requests')
    op.drop_index('REQUESTS_TYP_STA_UPD_IDX_OLD', 'requests')
    op.create_index('REQUESTS_TYP_STA_UPD_IDX', 'requests', ['request_type', 'state', 'updated_at'])
