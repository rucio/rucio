"""
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Vincent Garonne, <vincent.garonne@cern.ch>, 2014-2017

change index on table requests

Revision ID: 35ef10d1e11b
Revises: 3152492b110b
Create Date: 2014-06-20 09:01:52.704794

"""

from alembic.op import create_index, drop_index

# revision identifiers, used by Alembic.
revision = '35ef10d1e11b'  # pylint:disable=invalid-name
down_revision = '3152492b110b'  # pylint:disable=invalid-name


def upgrade():
    '''
    upgrade method
    '''
    create_index('REQUESTS_TYP_STA_UPD_IDX', 'requests', ["request_type", "state", "updated_at"])
    drop_index('REQUESTS_TYP_STA_CRE_IDX', 'requests')


def downgrade():
    '''
    downgrade method
    '''
    create_index('REQUESTS_TYP_STA_CRE_IDX', 'requests', ["request_type", "state", "created_at"])
    drop_index('REQUESTS_TYP_STA_UPD_IDX', 'requests')
