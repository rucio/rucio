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

''' Fix primary key for subscription_history '''

from alembic.op import create_primary_key, drop_constraint

from rucio.db.sqla.migrate_repo import is_current_dialect

# Alembic revision identifiers
revision = 'b5493606bbf5'
down_revision = 'a08fa8de1545'


def upgrade():
    '''
    Upgrade the database to this revision
    '''
    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        drop_constraint(constraint_name='SUBSCRIPTIONS_PK', table_name='subscriptions_history', type_='primary')
        create_primary_key('SUBSCRIPTIONS_HISTORY_PK', 'subscriptions_history', ['id', 'updated_at'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''
    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        drop_constraint(constraint_name='SUBSCRIPTIONS_HISTORY_PK', table_name='subscriptions_history', type_='primary')
        create_primary_key('SUBSCRIPTIONS_PK', 'subscriptions_history', ['id', 'updated_at'])
