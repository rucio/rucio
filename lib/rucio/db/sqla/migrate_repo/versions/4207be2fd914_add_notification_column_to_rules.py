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

from rucio.db.sqla.constants import RuleNotification
from rucio.db.sqla.migrate_repo import (
    add_column,
    drop_column,
    get_backend_enum,
    is_current_dialect,
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

    rules_notification_type = get_backend_enum(RuleNotification, name='RULES_NOTIFICATION_CHK')

    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        add_column(
            'rules',
            sa.Column('notification', rules_notification_type, default=RuleNotification.NO),
        )


def downgrade():
    """
    Downgrade the database to the previous revision
    """

    if is_current_dialect('oracle'):
        try_drop_constraint('RULES_NOTIFICATION_CHK', 'rules')
        drop_column('rules', 'notification')

    elif is_current_dialect('postgresql'):
        try_drop_constraint('RULES_NOTIFICATION_CHK', 'rules')
        drop_column('rules', 'notification')
        try_drop_enum('RULES_NOTIFICATION_CHK')

    elif is_current_dialect('mysql'):
        drop_column('rules', 'notification')
