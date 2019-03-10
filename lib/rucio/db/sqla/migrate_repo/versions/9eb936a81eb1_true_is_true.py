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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019

''' true is true '''

from alembic import context, op


# Alembic revision identifiers
revision = '9eb936a81eb1'
down_revision = 'b96a1c7e1cc4'


# IMPORTANT: Only execute this after you're running the new release.
#            Do not change the values while still running the previous release.
#            This update potentially requires a manual change of database contents!


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    # First, change all uppercase booleanstrings to lowercase booleanstrings
    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''
        op.execute("UPDATE " + schema + "account_attr_map SET value='true' WHERE value='True'")  # pylint: disable=no-member
        op.execute("UPDATE " + schema + "account_attr_map SET value='false' WHERE value='False'")  # pylint: disable=no-member
        op.execute("UPDATE " + schema + "rse_attr_map SET value='true' WHERE value='True'")  # pylint: disable=no-member
        op.execute("UPDATE " + schema + "rse_attr_map SET value='false' WHERE value='False'")  # pylint: disable=no-member

    # Second, change __all__  0/1 which represent booleans to true/false.
    # This cannot be done automatically, as there might be 0/1 values which really are integers.
    #
    # Must be done selectively by the operator:
    # UPDATE account_attr_map SET value='true' WHERE value='1' AND ..
    # UPDATE account_attr_map SET value='false' WHERE value='0' AND ..
    # UPDATE rse_attr_map SET value='true' WHERE value='1' AND ..
    # UPDATE rse_attr_map SET value='false' WHERE value='0' AND ..


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    # First, change all lowercase booleanstrings to uppercase booleanstrings
    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''
        op.execute("UPDATE " + schema + "account_attr_map SET value='True' WHERE value='true'")  # pylint: disable=no-member
        op.execute("UPDATE " + schema + "account_attr_map SET value='False' WHERE value='false'")  # pylint: disable=no-member
        op.execute("UPDATE " + schema + "rse_attr_map SET value='True' WHERE value='true'")  # pylint: disable=no-member
        op.execute("UPDATE " + schema + "rse_attr_map SET value='False' WHERE value='false'")  # pylint: disable=no-member

    # Second, change __selected__ true/false to 0/1. This cannot be done
    # automatically, as we don't know which ones were previously stored as INT.
    #
    # Must be done selectively by the operator:
    # UPDATE account_attr_map SET value='1' WHERE value='true' AND ..
    # UPDATE account_attr_map SET value='0' WHERE value='false' AND ..
    # UPDATE rse_attr_map SET value='1' WHERE value='true' AND ..
    # UPDATE rse_attr_map SET value='0' WHERE value='false' AND ..
