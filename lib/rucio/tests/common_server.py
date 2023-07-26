# -*- coding: utf-8 -*-
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
import copy

from sqlalchemy import and_, delete, exists, select
from sqlalchemy.orm import aliased

from rucio.core import config as core_config
from rucio.core.vo import map_vo
from rucio.db.sqla import models
from rucio.db.sqla.session import transactional_session, get_session
from .common import get_long_vo

# Functions containing server-only includes that can't be included in client tests
# For each table, get the foreign key constraints from all other tables towards this table.
INBOUND_FOREIGN_KEYS = {}
for __table in models.BASE.metadata.tables.values():
    for __fk in __table.foreign_key_constraints:
        INBOUND_FOREIGN_KEYS.setdefault(__fk.referred_table, set()).add(__fk)


def _dependency_paths(stack, nb_times_in_stack, cur_table):
    """
    Generates lists of foreign keys: paths starting at cur_table and
    navigating the table graph via foreign key constraints.

    For example: As of time of writing, for cur_table = models.ReplicationRule.__table__,
    it will generate
        [DATASET_LOCKS_RULE_ID_FK]                            # rule.id <-> dataset_locks.rule_id
        [LOCKS_RULE_ID_FK]                                    # rule.id <-> locks.rule_id
        [RULES_CHILD_RULE_ID_FK, DATASET_LOCKS_RULE_ID_FK]    # rule.id <-> rule(alias).child_rule_id, rule(alias).id <-> dataset_locks.rule_id
        [RULES_CHILD_RULE_ID_FK, LOCKS_RULE_ID_FK]            # rule.id <-> rule(alias).child_rule_id, rule(alias).id <-> locks.rule_id
        [RULES_CHILD_RULE_ID_FK]                              # rule.id <-> rule(alias).child_rule_id
    """
    nb_times_in_stack[cur_table] = nb_times_in_stack.get(cur_table, 0) + 1

    for fk in INBOUND_FOREIGN_KEYS.get(cur_table, []):
        if nb_times_in_stack.get(fk.table, 0) > 1:
            # Only allow a table to appear twice in the stack.
            # This handles recursive constraints (like the one between rules and itself)
            continue
        stack.append(fk)
        yield from _dependency_paths(stack, nb_times_in_stack, fk.table)

    if stack:
        yield copy.copy(stack)
        fk = stack.pop()
        nb_times_in_stack[fk.table] -= 1


@transactional_session
def cleanup_db_deps(model, select_rows_stmt, *, session=None):
    """
    Removes rows which have foreign key constraints pointing to rows
    selected by `select_rows_stmt` in `model`. The deletion is transitive.
    This implements a behavior similar to "ON DELETE CASCADE", but without
    removing the initial rows from `model`, only their dependencies.
    """

    for fk_path in _dependency_paths(stack=[], nb_times_in_stack={}, cur_table=model.__table__):
        seen_tables = set()
        referred_table = model.__table__
        current_table = fk_path[-1].table
        filters = []
        for i, fk in enumerate(fk_path):
            current_table = fk.table
            if current_table in seen_tables:
                current_table = aliased(current_table)
            else:
                seen_tables.add(current_table)

            filters.append(and_(current_table.columns.get(e.parent.name) == referred_table.columns.get(e.column.name) for e in fk.elements))
            referred_table = current_table

        if session.bind.dialect.name == 'mysql':
            stmt = delete(
                current_table
            ).where(
                and_(*filters)
            ).where(
                select_rows_stmt
            )
        else:
            stmt = delete(
                current_table,
            ).where(
                exists(
                    select(
                        1
                    ).where(
                        and_(*filters)
                    ).where(
                        select_rows_stmt
                    )
                )
            )

        stmt = stmt.execution_options(
            synchronize_session=False
        )

        session.execute(stmt)


def reset_config_table():
    """ Clear the config table and install any default entires needed for the tests.
    """
    db_session = get_session()
    db_session.query(models.Config).delete()
    db_session.commit()
    core_config.set("vo-map", "testvo1", "tst")
    core_config.set("vo-map", "testvo2", "ts2")


def get_vo():
    """ Gets the current short/mapped VO name for testing.
    Maps the vo name to the short name, if configured.
    :returns: VO name string.
    """
    return map_vo(get_long_vo())
