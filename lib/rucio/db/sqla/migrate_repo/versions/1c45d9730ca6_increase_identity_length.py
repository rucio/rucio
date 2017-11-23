'''
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Mario Lassnig, <mario.lassnig@cern.ch>, 2017

increase identity length

Revision ID: 1c45d9730ca6
Revises: c5c0418f31aa
Create Date: 2017-10-31 17:52:21.313035

'''
from alembic.op import alter_column, create_check_constraint, drop_constraint
from alembic import context

import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1c45d9730ca6'  # pylint: disable=invalid-name
down_revision = 'b4293a99f344'  # pylint: disable=invalid-name


def upgrade():
    '''
    upgrade method
    '''
    alter_column('tokens', 'identity',
                 existing_type=sa.String(255),
                 type_=sa.String(2048))
    alter_column('identities', 'identity',
                 existing_type=sa.String(255),
                 type_=sa.String(2048))
    alter_column('account_map', 'identity',
                 existing_type=sa.String(255),
                 type_=sa.String(2048))

    if context.get_context().dialect.name not in ('sqlite', 'mysql'):
        drop_constraint('IDENTITIES_TYPE_CHK', 'identities', type_='check')
        create_check_constraint(name='IDENTITIES_TYPE_CHK',
                                source='identities',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH')")
        drop_constraint('ACCOUNT_MAP_ID_TYPE_CHK', 'account_map', type_='check')
        create_check_constraint(name='ACCOUNT_MAP_ID_TYPE_CHK',
                                source='account_map',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH')")


def downgrade():
    '''
    downgrade method
    '''

    # attention!
    # we would have to delete all SSH entries so we can shrink the colum.
    # since we don't want this to happen automatically, this part of the downgrade is disabled

    # alter_column('tokens', 'identity',
    #              existing_type=sa.String(2048),
    #              type_=sa.String(255))
    # alter_column('identities', 'identity',
    #              existing_type=sa.String(2048),
    #              type_=sa.String(255))
    # alter_column('account_map', 'identity',
    #              existing_type=sa.String(2048),
    #              type_=sa.String(255))

    if context.get_context().dialect.name not in ('sqlite', 'mysql'):
        drop_constraint('IDENTITIES_TYPE_CHK', 'identities', type_='check')
        create_check_constraint(name='IDENTITIES_TYPE_CHK',
                                source='identities',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS')")
        drop_constraint('ACCOUNT_MAP_ID_TYPE_CHK', 'account_map', type_='check')
        create_check_constraint(name='ACCOUNT_MAP_ID_TYPE_CHK',
                                source='account_map',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS')")
