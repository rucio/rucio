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

"""Add OIDC_ALL identity type."""

from alembic import context
from alembic.op import create_check_constraint, execute, get_bind
from sqlalchemy import inspect

from rucio.db.sqla.util import try_drop_constraint

# Alembic revision identifiers
revision = '96301768a11d'
down_revision = '3b943000da18'

IDENTITY_TYPES = ('X509', 'GSS', 'USERPASS', 'SSH', 'SAML', 'OIDC')
IDENTITY_TYPE_CONSTRAINTS = (
    ('identities', 'IDENTITIES_TYPE_CHK'),
    ('account_map', 'ACCOUNT_MAP_ID_TYPE_CHK'),
)


def _replace_identity_type_constraints(identity_types):
    migration_context = context.get_context()
    dialect = migration_context.dialect.name
    if dialect not in ('oracle', 'mysql', 'postgresql'):
        return

    schema = f'{migration_context.version_table_schema}.' if migration_context.version_table_schema else ''
    condition = "identity_type in (%s)" % ', '.join(repr(type_) for type_ in identity_types)
    for table_name, constraint_name in IDENTITY_TYPE_CONSTRAINTS:
        constraint_exists = context.is_offline_mode() or dialect == 'oracle' or constraint_name in {
            constraint['name']
            for constraint in inspect(get_bind()).get_check_constraints(
                table_name, schema=migration_context.version_table_schema
            )
        }
        if not constraint_exists:
            continue
        if dialect == 'mysql':
            execute(f'ALTER TABLE {schema}{table_name} DROP CHECK {constraint_name}')
        else:
            try_drop_constraint(constraint_name, table_name)
        create_check_constraint(constraint_name, table_name, condition)


def upgrade():
    """Upgrade the database to this revision."""
    _replace_identity_type_constraints((*IDENTITY_TYPES, 'OIDC_ALL'))


def downgrade():
    """Downgrade the database to the previous revision."""
    _replace_identity_type_constraints(IDENTITY_TYPES)
