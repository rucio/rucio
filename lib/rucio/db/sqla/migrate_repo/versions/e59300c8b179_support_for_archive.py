# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2015-2017

"""support for archive

Revision ID: e59300c8b179
Revises: 6e572a9bfbf3
Create Date: 2017-02-08 09:58:58.700799

"""

from alembic.op import (create_table, create_primary_key, create_foreign_key, add_column,
                        create_index, drop_column, drop_table)
from alembic import context
import sqlalchemy as sa

from rucio.db.sqla.models import String
from rucio.db.sqla.types import GUID

# revision identifiers, used by Alembic.
revision = 'e59300c8b179'
down_revision = '6e572a9bfbf3'


def upgrade():
    '''
    upgrade method
    '''
    create_table('archive_contents',
                 sa.Column('child_scope', String(25)),
                 sa.Column('child_name', String(255)),
                 sa.Column('scope', String(25)),
                 sa.Column('name', String(255)),
                 sa.Column('bytes', sa.BigInteger),
                 sa.Column('adler32', String(8)),
                 sa.Column('md5', String(32)),
                 sa.Column('guid', GUID()),
                 sa.Column('length', sa.BigInteger))

    create_table('archive_contents_history',
                 sa.Column('child_scope', String(25)),
                 sa.Column('child_name', String(255)),
                 sa.Column('scope', String(25)),
                 sa.Column('name', String(255)),
                 sa.Column('bytes', sa.BigInteger),
                 sa.Column('adler32', String(8)),
                 sa.Column('md5', String(32)),
                 sa.Column('guid', GUID()),
                 sa.Column('length', sa.BigInteger))

    if context.get_context().dialect.name != 'sqlite':
        create_primary_key('ARCH_CONTENTS_PK',
                           'archive_contents',
                           ['scope', 'name', 'child_scope', 'child_name'])
        create_foreign_key('ARCH_CONTENTS_PARENT_FK', 'archive_contents', 'dids',
                           ['scope', 'name'], ['scope', 'name'])
        create_foreign_key('ARCH_CONTENTS_CHILD_FK', 'archive_contents', 'dids',
                           ['child_scope', 'child_name'], ['scope', 'name'])

        create_index('ARCH_CONTENTS_CHILD_IDX', 'archive_contents',
                     ['child_scope', 'child_name', 'scope', 'name'])

        create_index('ARCH_CONT_HIST_IDX', 'archive_contents_history',
                     ['scope', 'name'])

        add_column('dids', sa.Column('is_archive',
                                     sa.Boolean(name='DIDS_ARCHIVE_CHK')))
        add_column('dids', sa.Column('constituent',
                                     sa.Boolean(name='DIDS_CONSTITUENT_CHK')))

        add_column('deleted_dids', sa.Column('is_archive', sa.Boolean()))
        add_column('deleted_dids', sa.Column('constituent', sa.Boolean()))


def downgrade():
    '''
    downgrade method
    '''
    drop_table('archive_contents')
    drop_table('archive_contents_history')
    if context.get_context().dialect.name != 'sqlite':
        drop_column('dids', 'is_archive')
        drop_column('dids', 'constituent')
        drop_column('deleted_dids', 'is_archive')
        drop_column('deleted_dids', 'constituent')
