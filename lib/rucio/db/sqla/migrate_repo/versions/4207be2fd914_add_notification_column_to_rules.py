# Copyright European Organization for Nuclear Research (CERN) since 2012
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

''' add notification column to rules '''

import sqlalchemy as sa
from alembic import op
from alembic.op import add_column, drop_column

from rucio.db.sqla.constants import RuleNotification
from rucio.db.sqla.migrate_repo import get_effective_schema, is_current_dialect
from rucio.db.sqla.util import try_drop_constraint

# Alembic revision identifiers
revision = '4207be2fd914'
down_revision = '14ec5aeb64cf'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    schema = get_effective_schema()
    schema_prefix = f"{schema}." if schema else ""

    if is_current_dialect('oracle', 'mysql'):
        add_column('rules', sa.Column('notification', sa.Enum(RuleNotification,
                                                              name='RULES_NOTIFICATION_CHK',
                                                              create_constraint=True,
                                                              values_callable=lambda obj: [e.value for e in obj]),
                                      default=RuleNotification.NO), schema=schema)
    elif is_current_dialect('postgresql'):
        op.execute("CREATE TYPE \"RULES_NOTIFICATION_CHK\" AS ENUM('Y', 'N', 'C', 'P')")
        op.execute("ALTER TABLE %srules ADD COLUMN notification \"RULES_NOTIFICATION_CHK\"" % schema_prefix)


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    schema = get_effective_schema()
    schema_prefix = f"{schema}." if schema else ""

    if is_current_dialect('oracle'):
        try_drop_constraint('RULES_NOTIFICATION_CHK', 'rules')
        drop_column('rules', 'notification', schema=schema)

    elif is_current_dialect('postgresql'):
        op.execute('ALTER TABLE %srules DROP CONSTRAINT IF EXISTS "RULES_NOTIFICATION_CHK", ALTER COLUMN notification TYPE CHAR' % schema_prefix)
        op.execute('ALTER TABLE %srules DROP COLUMN notification' % schema_prefix)
        op.execute('DROP TYPE \"RULES_NOTIFICATION_CHK\"')

    elif is_current_dialect('mysql'):
        drop_column('rules', 'notification', schema=schema)
