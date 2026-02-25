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

""" true is true """

from alembic.op import execute

from rucio.db.sqla.migrate_repo import is_current_dialect, qualify_table

# Alembic revision identifiers
revision = '9eb936a81eb1'
down_revision = 'b96a1c7e1cc4'


# IMPORTANT: Only execute this after you're running the new release.
#            Do not change the values while still running the previous release.
#            This update potentially requires a manual change of database contents!


def upgrade():
    """
    Upgrade the database to this revision
    """

    account_attr_table = qualify_table('account_attr_map')
    rse_attr_table = qualify_table('rse_attr_map')

    # First, change all uppercase booleanstrings to lowercase booleanstrings
    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        execute(
            f"""
            UPDATE {account_attr_table}
            SET value='true'
            WHERE value='True'
            """
        )
        execute(
            f"""
            UPDATE {account_attr_table}
            SET value='false'
            WHERE value='False'
            """
        )
        execute(
            f"""
            UPDATE {rse_attr_table}
            SET value='true'
            WHERE value='True'
            """
        )
        execute(
            f"""
            UPDATE {rse_attr_table}
            SET value='false'
            WHERE value='False'
            """
        )

    # Second, change __all__  0/1 which represent booleans to true/false.
    # This cannot be done automatically, as there might be 0/1 values which really are integers.
    #
    # Must be done selectively by the operator:
    # UPDATE account_attr_map SET value='true' WHERE value='1' AND ..
    # UPDATE account_attr_map SET value='false' WHERE value='0' AND ..
    # UPDATE rse_attr_map SET value='true' WHERE value='1' AND ..
    # UPDATE rse_attr_map SET value='false' WHERE value='0' AND ..


def downgrade():
    """
    Downgrade the database to the previous revision
    """

    account_attr_table = qualify_table('account_attr_map')
    rse_attr_table = qualify_table('rse_attr_map')

    # First, change all lowercase booleanstrings to uppercase booleanstrings
    if is_current_dialect('oracle', 'mysql', 'postgresql'):
        execute(
            f"""
            UPDATE {account_attr_table}
            SET value='True'
            WHERE value='true'
            """
        )
        execute(
            f"""
            UPDATE {account_attr_table}
            SET value='False'
            WHERE value='false'
            """
        )
        execute(
            f"""
            UPDATE {rse_attr_table}
            SET value='True'
            WHERE value='true'
            """
        )
        execute(
            f"""
            UPDATE {rse_attr_table}
            SET value='False'
            WHERE value='false'
            """
        )

    # Second, change __selected__ true/false to 0/1. This cannot be done
    # automatically, as we don't know which ones were previously stored as INT.
    #
    # Must be done selectively by the operator:
    # UPDATE account_attr_map SET value='1' WHERE value='true' AND ..
    # UPDATE account_attr_map SET value='0' WHERE value='false' AND ..
    # UPDATE rse_attr_map SET value='1' WHERE value='true' AND ..
    # UPDATE rse_attr_map SET value='0' WHERE value='false' AND ..
