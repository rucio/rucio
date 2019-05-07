# Copyright 2013-2019 CERN for the benefit of the ATLAS collaboration.
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
#
# Authors:
# - Robert Illingworth <illingwo@fnal.gov>, 2019

''' postgres_use_check_constraints '''

from alembic import context
from alembic.op import (create_foreign_key, drop_constraint, execute)


# Alembic revision identifiers
revision = 'f1b14a8c2ac1'
down_revision = 'b8caac94d7f0'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name != 'postgresql':
        return

    # depending on the creation/migration history of the schema it may or
    # may not already be using check constraints.

    schema = context.get_context().version_table_schema if context.get_context().version_table_schema else None

    # drop foreign keys where the type changes
    drop_constraint('ACCOUNT_MAP_ID_TYPE_FK', 'account_map', schema=schema, type_='foreignkey')

    did_types = ('A', 'C', 'D', 'F', 'Y', 'X', 'Z')
    types_to_drop = set()
    for table, column, constraint_name, constraint in (
            ('account_map', 'identity_type', "ACCOUNT_MAP_ID_TYPE_CHK", ('X509', 'GSS', 'USERPASS', 'SSH')),
            ('accounts', 'account_type', "ACCOUNTS_TYPE_CHK", ('GROUP', 'USER', 'SERVICE')),
            ('accounts', 'status', "ACCOUNTS_STATUS_CHK", ('ACTIVE', 'DELETED', 'SUSPENDED')),
            ('bad_pfns', 'state', 'BAD_PFNS_STATE_CHK', ('A', 'S', 'B', 'T')),
            ('bad_replicas', 'state', 'BAD_REPLICAS_STATE_CHK', ('B', 'D', 'L', 'S', 'R', 'T')),
            ('collection_replicas', 'did_type', "COLLECTION_REPLICAS_TYPE_CHK", did_types),
            ('collection_replicas', 'state', "COLLECTION_REPLICAS_STATE_CHK", ('A', 'C', 'B', 'D', 'S', 'U', 'T')),
            ('contents', 'did_type', "CONTENTS_DID_TYPE_CHK", did_types),
            ('contents', 'child_type', "CONTENTS_CHILD_TYPE_CHK", ('A', 'C', 'D', 'F', 'Y', 'X', 'Z')),
            ('contents_history', 'did_type', "CONTENTS_HIST_DID_TYPE_CHK", did_types),
            ('contents_history', 'child_type', "CONTENTS_HIST_CHILD_TYPE_CHK", ('A', 'C', 'D', 'F', 'Y', 'X', 'Z')),
            ('naming_conventions', 'convention_type', "CVT_TYPE_CHK", ('ALL', 'CONTAINER', 'DERIVED', 'COLLECTION', 'DATASET', 'FILE')),
            ('dataset_locks', 'state', "DATASET_LOCKS_STATE_CHK", ('S', 'R', 'O')),
            ('deleted_dids', 'did_type', "DEL_DIDS_TYPE_CHK", did_types),
            ('deleted_dids', 'availability', "DEL_DIDS_AVAIL_CHK", ('A', 'D', 'L')),
            ('did_keys', 'key_type', "DID_KEYS_TYPE_CHK", ('ALL', 'CONTAINER', 'DERIVED', 'COLLECTION', 'DATASET', 'FILE')),
            ('dids', 'did_type', "DIDS_TYPE_CHK", did_types),
            ('dids', 'availability', "DIDS_AVAILABILITY_CHK", ('A', 'D', 'L')),
            ('identities', 'identity_type', "IDENTITIES_TYPE_CHK", ('X509', 'GSS', 'USERPASS', 'SSH')),
            ('lifetime_except', 'did_type', "LIFETIME_EXCEPT_TYPE_CHK", did_types),
            ('lifetime_except', 'state', "LIFETIME_EXCEPT_STATE_CHK", ('A', 'R', 'W')),
            ('locks', 'state', "LOCKS_STATE_CHK", ('S', 'R', 'O')),
            ('replicas', 'state', 'REPLICAS_STATE_CHK', ('A', 'U', 'C', 'B', 'D', 'S', 'T')),
            ('requests', 'request_type', "REQUESTS_TYPE_CHK", ('I', 'U', 'T', 'O', 'D')),
            ('requests', 'did_type', "REQUESTS_DIDTYPE_CHK", did_types),
            ('requests', 'state', "REQUESTS_STATE_CHK", ('A', 'D', 'G', 'F', 'M', 'L', 'O', 'N', 'Q', 'S', 'U', 'W')),
            ('rses', 'rse_type', "RSES_TYPE_CHK", ('DISK', 'TAPE')),
            ('rules', 'did_type', "RULES_DID_TYPE_CHK", did_types),
            ('rules', 'state', "RULES_STATE_CHK", ('I', 'O', 'S', 'R', 'U', 'W')),
            ('rules', 'grouping', "RULES_GROUPING_CHK", ('A', 'D', 'N')),
            ('rules', 'notification', "RULES_NOTIFICATION_CHK", ('Y', 'P', 'C', 'N')),
            ('rules_history', 'did_type', "RULES_HISTORY_DIDTYPE_CHK", did_types),
            ('rules_history', 'state', "RULES_HISTORY_STATE_CHK", ('I', 'O', 'S', 'R', 'U', 'W')),
            ('rules_history', 'grouping', "RULES_HISTORY_GROUPING_CHK", ('A', 'D', 'N')),
            ('rules_history', 'notification', "RULES_HISTORY_NOTIFY_CHK", ('Y', 'P', 'C', 'N')),
            ('rules_hist_recent', 'did_type', "RULES_HIST_RECENT_DIDTYPE_CHK", did_types),
            ('rules_hist_recent', 'state', "RULES_HIST_RECENT_STATE_CHK", ('I', 'O', 'S', 'R', 'U', 'W')),
            ('rules_hist_recent', 'grouping', "RULES_HIST_RECENT_GROUPING_CHK", ('A', 'D', 'N')),
            ('rules_hist_recent', 'notification', "RULES_HIST_RECENT_NOTIFY_CHK", ('Y', 'P', 'C', 'N')),
            ('scopes', 'status', "SCOPE_STATUS_CHK", ('C', 'D', 'O')),
            ('subscriptions', 'state', "SUBSCRIPTIONS_STATE_CHK", ('I', 'A', 'B', 'U', 'N')),
            ('updated_col_rep', 'did_type', "UPDATED_COL_REP_TYPE_CHK", did_types),
            ('updated_dids', 'rule_evaluation_action', "UPDATED_DIDS_RULE_EVAL_ACT_CHK", ('A', 'D')),
    ):

        args = {'schema': '%s.' % schema if schema else '',
                'table': table,
                'column': column,
                'constraint_name': constraint_name,
                'constraint': ', '.join("'%s'" % con for con in constraint),
                'size': max(len(con) for con in constraint)
                }
        execute("""ALTER TABLE %(schema)s%(table)s
                    DROP CONSTRAINT IF EXISTS "%(constraint_name)s",
                    ALTER COLUMN %(column)s TYPE varchar(%(size)d) USING %(column)s::text,
                    ADD CONSTRAINT "%(constraint_name)s" CHECK (%(column)s in (%(constraint)s))""" % args)
        types_to_drop.add(constraint_name)

    # four history tables
    for table, column, in (
            ('requests_history', 'did_type'),
            ('requests_history', 'request_type'),
            ('requests_history', 'state'),
            ('subscriptions_history', 'state'),
    ):
        args = {'schema': '%s.' % schema if schema else '',
                'table': table,
                'column': column,
                'size': 1,
                }
        execute("""ALTER TABLE %(schema)s%(table)s
                   ALTER COLUMN %(column)s TYPE varchar(%(size)d) USING %(column)s::text""" % args)

    # put back the foreign keys
    create_foreign_key('ACCOUNT_MAP_ID_TYPE_FK', 'account_map', 'identities', ['identity', 'identity_type'], ['identity', 'identity_type'], source_schema=schema, referent_schema=schema)

    # now drop the types - nothing should use them now
    for constraint_name in types_to_drop:
        execute('DROP TYPE IF EXISTS "%s"' % constraint_name)


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    # downgrading is too complex. The upgrade should be idempotent, so down then up will still work.
