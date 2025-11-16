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

""" add a new state LOST in BadFilesStatus """


from rucio.db.sqla.migrate_repo import (
    create_check_constraint,
    is_current_dialect,
    try_drop_constraint,
)

# Alembic revision identifiers
revision = '3d9813fab443'
down_revision = '1fc15ab60d43'


def upgrade():
    """
    Upgrade the database to this revision
    """

    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        create_check_constraint(constraint_name='BAD_REPLICAS_STATE_CHK', table_name='bad_replicas',
                                condition="state in ('B', 'D', 'L', 'R', 'S')")


def downgrade():

    """
    Downgrade the database to the previous revision
    """

    if is_current_dialect('oracle', 'postgresql'):
        try_drop_constraint('BAD_REPLICAS_STATE_CHK', 'bad_replicas')
