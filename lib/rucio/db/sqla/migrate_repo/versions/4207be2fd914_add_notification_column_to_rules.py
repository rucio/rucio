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

""" add notification column to rules """

import sqlalchemy as sa
from alembic.op import execute

from rucio.db.sqla.constants import RuleNotification
from rucio.db.sqla.migrate_repo import (
    add_column,
    drop_column,
    enum_values_clause,
    is_current_dialect,
    qualify_table,
    render_enum_name,
    try_drop_constraint,
    try_drop_enum,
)

# Alembic revision identifiers
revision = '4207be2fd914'
down_revision = '14ec5aeb64cf'


def upgrade():
    """
    Upgrade the database to this revision
    """

    rules_table = qualify_table('rules')
    rules_notification_values = ['Y', 'N', 'C', 'P']

    if is_current_dialect('oracle', 'mysql'):
        add_column('rules', sa.Column('notification', sa.Enum(RuleNotification,
                                                              name='RULES_NOTIFICATION_CHK',
                                                              create_constraint=True,
                                                              values_callable=lambda obj: [e.value for e in obj]),
                                      default=RuleNotification.NO))
    elif is_current_dialect('postgresql'):
        rules_notification_enum = render_enum_name('RULES_NOTIFICATION_CHK')
        execute(
            f"""
            CREATE TYPE {rules_notification_enum} AS ENUM({enum_values_clause(rules_notification_values)})
            """
        )
        execute(
            f"""
            ALTER TABLE {rules_table}
            ADD COLUMN notification {rules_notification_enum}
            """
        )


def downgrade():
    """
    Downgrade the database to the previous revision
    """

    rules_table = qualify_table('rules')

    if is_current_dialect('oracle'):
        try_drop_constraint('RULES_NOTIFICATION_CHK', 'rules')
        drop_column('rules', 'notification')

    elif is_current_dialect('postgresql'):
        execute(
            f"""
            ALTER TABLE {rules_table}
            DROP CONSTRAINT IF EXISTS "RULES_NOTIFICATION_CHK",
            ALTER COLUMN notification TYPE CHAR
            """
        )
        execute(
            f"""
            ALTER TABLE {rules_table}
            DROP COLUMN notification
            """
        )
        try_drop_enum('RULES_NOTIFICATION_CHK')

    elif is_current_dialect('mysql'):
        drop_column('rules', 'notification')
