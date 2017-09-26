'''
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Vincent Garonne, <vincent.garonne@cern.ch>, 2015-2017

${message}

Revision ID: ${up_revision}
Revises: ${down_revision}
Create Date: ${create_date}

'''
from alembic.op import (create_primary_key, create_check_constraint,
                        drop_constraint, rename_table)

from alembic import context

import sqlalchemy as sa
${imports if imports else ""}

# revision identifiers, used by Alembic.
revision = ${repr(up_revision)}  # pylint: disable=invalid-name
down_revision = ${repr(down_revision)}  # pylint: disable=invalid-name


def upgrade():
    '''
    upgrade method
    '''
    if context.get_context().dialect.name != 'sqlite':
        ${upgrades if upgrades else "pass"}


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name != 'sqlite':
        ${downgrades if downgrades else "pass"}
