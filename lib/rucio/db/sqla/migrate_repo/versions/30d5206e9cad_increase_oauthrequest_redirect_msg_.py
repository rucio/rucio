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

"""Increase OAuthRequest.redirect_msg length"""    # noqa: D400, D415

import sqlalchemy as sa
from alembic.op import alter_column

from rucio.db.sqla.migrate_repo import get_effective_schema, is_current_dialect

# Alembic revision identifiers
revision = '30d5206e9cad'
down_revision = 'b0070f3695c8'


def upgrade():
    """Upgrade the database to this revision."""
    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        schema = get_effective_schema()
        alter_column('oauth_requests', 'redirect_msg', existing_type=sa.String(2048), type_=sa.String(4000), schema=schema)


def downgrade():
    """Downgrade the database to the previous revision."""
    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        schema = get_effective_schema()
        alter_column('oauth_requests', 'redirect_msg', existing_type=sa.String(4000), type_=sa.String(2048), schema=schema)
