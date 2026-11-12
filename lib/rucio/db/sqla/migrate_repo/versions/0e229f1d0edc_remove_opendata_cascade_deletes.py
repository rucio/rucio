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

"""remove opendata cascade deletes"""    # noqa: D400, D415

from alembic import context, op

# Alembic revision identifiers
revision = '0e229f1d0edc'
down_revision = '3b943000da18'


OPENDATA_FOREIGN_KEYS = (
    ('dids_opendata_doi', 'dids_opendata', 'OPENDATA_DOI_FK'),
    ('dids_opendata_record', 'dids_opendata', 'OPENDATA_RECORD_FK'),
    ('dids_opendata_meta', 'dids_opendata', 'OPENDATA_META_FK'),
    ('dids_opendata', 'dids', 'OPENDATA_DID_FK'),
)


def _replace_foreign_keys(ondelete):
    schema = context.get_context().version_table_schema

    for table, referenced_table, constraint in OPENDATA_FOREIGN_KEYS:
        op.drop_constraint(
            constraint,
            table,
            type_='foreignkey',
            schema=schema,
        )
        op.create_foreign_key(
            constraint,
            table,
            referenced_table,
            ['scope', 'name'],
            ['scope', 'name'],
            source_schema=schema,
            referent_schema=schema,
            ondelete=ondelete,
        )


def upgrade():
    """Upgrade the database to this revision."""
    if context.get_context().dialect.name in ('oracle', 'postgresql', 'mysql'):
        _replace_foreign_keys(ondelete=None)


def downgrade():
    """Downgrade the database to the previous revision."""
    if context.get_context().dialect.name in ('oracle', 'postgresql', 'mysql'):
        _replace_foreign_keys(ondelete='CASCADE')
