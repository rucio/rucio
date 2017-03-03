'''
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Vincent Garonne, <vincent.garonne@cern.ch>, 2014-2017

create index on requests.external_id

Revision ID: 42db2617c364
Revises: 4bab9edd01fc
Create Date: 2015-03-23 11:56:44.690512
'''

from alembic.op import create_index, drop_index

# revision identifiers, used by Alembic.
revision = '42db2617c364'  # pylint: disable=invalid-name
down_revision = '4bab9edd01fc'  # pylint: disable=invalid-name


def upgrade():
    '''
    upgrade method
    '''
    create_index('REQUESTS_EXTERNALID_UQ', 'requests', ['external_id'])


def downgrade():
    '''
    downgrade method
    '''
    drop_index('REQUESTS_EXTERNALID_UQ', 'requests')
