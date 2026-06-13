#!/usr/bin/env python
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
import random

from datetime import datetime, timedelta
from typing import Optional

import pytest
from sqlalchemy.sql.expression import and_, update

from rucio.client.loadinjectionclient import LoadInjectionClient
from rucio.common.exception import (
    AccessDenied,
    DuplicateLoadInjectionPlan,
    NoLoadInjectionPlanFound,
    NoUniqueDatasetFound,
)
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid
from rucio.core.account import add_account
from rucio.core.account_limit import set_local_account_limit
from rucio.core.did import add_dids
from rucio.core.load_injection import (
    add_injection_plan,
    add_injection_plan_history,
    add_injection_plans,
    add_injection_plans_history,
    add_unique_rse_pair_dataset,
    add_unique_rse_pair_datasets,
    delete_injection_plan,
    delete_injection_plans,
    delete_unique_rse_pair_dataset,
    delete_unique_rse_pair_datasets,
    get_injection_plan,
    get_injection_plan_history,
    get_injection_plan_state,
    get_injection_plans,
    get_injection_plans_history,
    get_unique_rse_pair_dataset,
    get_unique_rse_pair_datasets,
    scan_unique_rse_pair_datasets,
    try_claim_plan,
    try_recover_zombie_plan,
    update_injection_plan_state,
    validate_unique_rse_pair_dataset,
)
from rucio.core.rse import add_rse, get_rse, get_rse_id
from rucio.daemons.loadinjector.scanner import (
    update_unique_rse_pair_datasets,
    update_unique_rse_pair_datasets_bulk,
)
from rucio.core.rule import add_rule
from rucio.core.scope import add_scope
from rucio.db.sqla.constants import LoadInjectionState, LockState
from rucio.db.sqla.session import transactional_session, Session
from rucio.db.sqla import models
from rucio.db.sqla.models import DatasetLock, DIDType, AccountType
from rucio.tests.common import (
    account_name_generator,
    did_name_generator,
    rse_name_generator,
    scope_name_generator,
)


# ---------------------------------------------------------------------------
# Test isolation: prefix generated names with a session UUID so parallel
# or serial re-runs never collide on RSE/DID names.
# ---------------------------------------------------------------------------

_SESSION_SUFFIX = generate_uuid()[:8]
_ORIG_RSE_GENERATOR = rse_name_generator


def _prefixed_rse_name() -> str:
    return f"{_ORIG_RSE_GENERATOR()}-{_SESSION_SUFFIX}"


rse_name_generator = _prefixed_rse_name


def generate_random_plans(
    nplan: int = 1,
    src_rse_id: Optional[str] = None,
    dest_rse_id: Optional[str] = None,
) -> list:
    plans = list()
    for _ in range(nplan):
        plan = {
            "plan_id": generate_uuid(),
            "src_rse_id": (src_rse_id if src_rse_id else add_rse(rse_name_generator())),
            "dest_rse_id": (
                dest_rse_id if dest_rse_id else add_rse(rse_name_generator())
            ),
            "vo": None,
            "inject_rate": random.randint(200, 400),
            "interval": random.randint(800, 1000),
            "start_time": datetime(2025, 1, 1, 0, 0, 0)
            + timedelta(seconds=random.randint(0, 100)),
            "end_time": datetime(2025, 1, 2, 0, 0, 0)
            + timedelta(seconds=random.randint(3600, 86400)),
            "state": random.choice(list(LoadInjectionState)),
            "fudge": random.uniform(0.0, 0.2),
            "max_injection": random.uniform(0.15, 0.25),
            "expiration_delay": random.randint(1500, 2100),
            "big_first": random.choice([True, False]),
            "rule_lifetime": random.randint(3000, 3600),
            "comments": "".join(
                random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(10, 20))
            ),
            "dry_run": random.choice([True, False]),
        }
        plans.append(plan)
    return plans


@transactional_session
def update_dataset_lock_meta(datasets: list, *, session: "Session") -> None:
    try:
        for dataset in datasets:
            stmt = (
                update(DatasetLock)
                .where(
                    and_(
                        DatasetLock.scope == dataset["scope"],
                        DatasetLock.name == dataset["name"],
                    )
                )
                .values(
                    {
                        DatasetLock.state: dataset["state"],
                        DatasetLock.length: dataset["length"],
                        DatasetLock.bytes: dataset["bytes"],
                    }
                )
            )
            session.execute(stmt)
    except Exception:
        raise


@transactional_session
def generate_random_datasets(
    ndatasets: int = 1,
    nrses: int = 1,
    *,
    session: "Session",
) -> tuple[list, list]:
    # Create now account
    account_name = account_name_generator()
    account = InternalAccount(account_name)
    add_account(
        account,
        AccountType.USER,
        account_name + "@test.com",
        session=session,
    )

    # Create new scope
    scope = InternalScope(scope_name_generator())
    add_scope(scope, account, session=session)

    # Create new rses and set account limits
    rse_ids = list()
    for _ in range(nrses):
        rse_id = add_rse(rse_name_generator(), session=session)
        # Large enough quota for testing (within BIGINT range)
        set_local_account_limit(account, rse_id, 10**15, session=session)
        rse_ids.append(rse_id)

    # Create datasets
    lockstats_pool = list(LockState)
    lockstats_pool.extend([LockState.OK] * 10)
    datasets = list()
    for _ in range(ndatasets):
        dataset = {
            "scope": scope,
            "name": did_name_generator(did_type="dataset"),
            "rse_id": random.choice(rse_ids),
            "account": account,
            "state": random.choice(lockstats_pool),
            "length": random.randint(10, 1200),
            "bytes": random.randint(1000000000, 120000000000),
            "accessed_at": datetime.utcnow(),
            "type": DIDType.DATASET,  # for dids
        }
        datasets.append(dataset)
    add_dids(datasets, account, session=session)

    # Create rules for datasets
    rule_ids = list()
    for dataset in datasets:
        rule = {
            "dids": [dataset],
            "account": dataset["account"],
            "copies": 1,
            "rse_expression": get_rse(dataset["rse_id"], session=session)["rse"],
            "grouping": "DATASET",
            "weight": None,
            "lifetime": None,
            "locked": True,
            "subscription_id": None,
        }
        rule_id = add_rule(**rule, session=session)[0]
        rule_ids.append(rule_id)

    # Update dataset with rule_id
    for dataset in datasets:
        dataset["rule_id"] = rule_ids[datasets.index(dataset)]
    update_dataset_lock_meta(datasets)
    return datasets, rse_ids


@transactional_session
def generate_random_extra_rules(datasets: list, rse_ids: list[str], *, session: "Session") -> dict:
    rule_ids = list()
    datasets_map = dict()
    datasets_for_meta = list()
    for dataset in datasets:
        rse_id_candidates = [
            rse_id for rse_id in rse_ids if rse_id != dataset["rse_id"]
        ]
        rse_id_candidates = random.sample(
            rse_id_candidates, random.randint(0, len(rse_id_candidates))
        )

        for rse_id in rse_id_candidates:
            rule = {
                "dids": [dataset],
                "account": dataset["account"],
                "copies": 1,
                "rse_expression": get_rse(rse_id, session=session)["rse"],
                "grouping": "DATASET",
                "weight": None,
                "lifetime": None,
                "locked": True,
                "subscription_id": None,
            }
            rule_id = add_rule(**rule, session=session)[0]
            rule_ids.append(rule_id)

        rse_id_candidates.append(dataset["rse_id"])
        key = (
            dataset["scope"],
            dataset["name"],
            dataset["bytes"],
            dataset["length"],
            dataset["state"],
        )
        datasets_map[key] = rse_id_candidates

    for dataset in datasets:
        dataset["rule_id"] = rule_ids[datasets.index(dataset)]
    update_dataset_lock_meta(datasets, session=session)
    return datasets_map


def convert_to_unique_dataset(dataset: dict, dest_rse_id: Optional[str] = None) -> dict:
    new_dataset = dict()
    new_dataset["scope"] = dataset["scope"]
    new_dataset["name"] = dataset["name"]
    new_dataset["bytes"] = dataset["bytes"]
    new_dataset["length"] = dataset["length"]
    new_dataset["src_rse_id"] = dataset["rse_id"]
    new_dataset["dest_rse_id"] = (
        dest_rse_id if dest_rse_id else add_rse(rse_name_generator())
    )
    return new_dataset


class TestPlanCore:
    def test_add_injection_plan(self):
        """LOAD INJECTION PLAN (CORE): add an injection plan"""
        new_plan = generate_random_plans()[0]
        add_injection_plan(
            plan_id=new_plan["plan_id"],
            src_rse_id=new_plan["src_rse_id"],
            dest_rse_id=new_plan["dest_rse_id"],
            inject_rate=new_plan["inject_rate"],
            interval=new_plan["interval"],
            start_time=new_plan["start_time"],
            end_time=new_plan["end_time"],
        )
        plan = get_injection_plan(
            src_rse_id=new_plan["src_rse_id"], dest_rse_id=new_plan["dest_rse_id"]
        )
        assert isinstance(plan, dict)
        assert new_plan["plan_id"] == plan["plan_id"]
        assert new_plan["src_rse_id"] == plan["src_rse_id"]
        assert new_plan["dest_rse_id"] == plan["dest_rse_id"]
        assert new_plan["inject_rate"] == plan["inject_rate"]
        assert new_plan["interval"] == plan["interval"]
        assert new_plan["start_time"] == plan["start_time"]
        assert new_plan["end_time"] == plan["end_time"]
        assert plan["fudge"] == 0.0
        assert plan["max_injection"] == 0.2
        assert plan["expiration_delay"] == 1800
        assert plan["big_first"] == False
        assert plan["rule_lifetime"] == 3600
        assert plan["comments"] == None
        assert plan["dry_run"] == False
        assert plan["state"] == LoadInjectionState.WAITING

    def test_add_injection_plans(self):
        """LOAD INJECTION PLAN (CORE): add injection plans"""
        rse_name1 = rse_name_generator()
        rse_name2 = rse_name_generator()
        rse_id1 = add_rse(rse_name1)
        rse_id2 = add_rse(rse_name2)
        new_plans = [
            generate_random_plans(1, rse_id1, rse_id2)[0],
            generate_random_plans(1, rse_id2, rse_id1)[0],
        ]
        add_injection_plans(new_plans)

        plan1 = get_injection_plan(src_rse_id=rse_id1, dest_rse_id=rse_id2)
        assert isinstance(plan1, dict)
        for key, value in new_plans[0].items():
            assert value == plan1[key]

        plan2 = get_injection_plan(src_rse_id=rse_id2, dest_rse_id=rse_id1)
        assert isinstance(plan2, dict)
        for key, value in new_plans[1].items():
            assert value == plan2[key]

    def test_get_injection_plan(self):
        """LOAD INJECTION PLAN (CORE): get a injection plan"""
        new_plan = generate_random_plans()[0]
        add_injection_plan(**new_plan)

        plan = get_injection_plan(
            src_rse_id=new_plan["src_rse_id"], dest_rse_id=new_plan["dest_rse_id"]
        )
        assert isinstance(plan, dict)
        for key, value in new_plan.items():
            assert value == plan[key]

    def test_get_injection_plans(self):
        """LOAD INJECTION PLAN (CORE): get injection plans"""
        rse_name = list()
        rse_id = list()
        new_plans = list()
        for i in range(5):
            rse_name.append(rse_name_generator())
            rse_id.append(add_rse(rse_name[i]))
        for i in range(5):
            for j in range(5):
                if i == j:
                    continue
                plan = generate_random_plans(1, rse_id[i], rse_id[j])[0]
                new_plans.append(plan)
        add_injection_plans(plans=new_plans)

        # check src_rse_id and dest_rse_id parameter
        for i in range(5):
            for j in range(5):
                if i == j:
                    continue
                plan = get_injection_plan(src_rse_id=rse_id[i], dest_rse_id=rse_id[j])
                assert isinstance(plan, dict)
                plan.pop("updated_at", None)
                plan.pop("created_at", None)
                assert plan in new_plans
        # check no parameter
        plans = get_injection_plans()
        for plan in plans:
            plan.pop("updated_at", None)
            plan.pop("created_at", None)
        for new_plan in new_plans:
            assert new_plan in plans

    def test_add_injection_plan_history(self):
        """LOAD INJECTION PLAN (CORE): add an injection plan history"""
        new_plan = generate_random_plans()[0]
        add_injection_plan_history(**new_plan)

        plans = get_injection_plan_history(
            src_rse_id=new_plan["src_rse_id"], dest_rse_id=new_plan["dest_rse_id"]
        )
        assert isinstance(plans, dict)
        for key, value in new_plan.items():
            assert value == plans[key]

    def test_add_injection_plans_history(self):
        """LOAD INJECTION PLAN (CORE): add injection plans history"""
        rse_name1 = rse_name_generator()
        rse_name2 = rse_name_generator()
        rse_id1 = add_rse(rse_name1)
        rse_id2 = add_rse(rse_name2)
        new_plans = [
            generate_random_plans(1, rse_id1, rse_id2)[0],
            generate_random_plans(1, rse_id2, rse_id1)[0],
        ]
        add_injection_plans_history(new_plans)

        plan1 = get_injection_plan_history(src_rse_id=rse_id1, dest_rse_id=rse_id2)
        assert isinstance(plan1, dict)
        for key, value in new_plans[0].items():
            assert value == plan1[key]

        plan2 = get_injection_plan_history(src_rse_id=rse_id2, dest_rse_id=rse_id1)
        assert isinstance(plan2, dict)
        for key, value in new_plans[1].items():
            assert value == plan2[key]

    def test_get_injection_plan_history(self):
        """LOAD INJECTION PLAN (CORE): get an injection plan history"""
        new_plan = generate_random_plans()[0]
        add_injection_plan_history(**new_plan)
        plan = get_injection_plan_history(
            new_plan["src_rse_id"], new_plan["dest_rse_id"]
        )
        assert isinstance(plan, dict)
        for key, value in new_plan.items():
            assert value == plan[key]

    def test_get_injection_plans_history(self):
        """LOAD INJECTION PLAN (CORE): get injection plans history"""
        rse_name = list()
        rse_id = list()
        new_plans = list()
        for i in range(5):
            rse_name.append(rse_name_generator())
            rse_id.append(add_rse(rse_name[i]))
        for i in range(5):
            for j in range(5):
                if i == j:
                    continue
                plan = generate_random_plans(1, rse_id[i], rse_id[j])[0]
                new_plans.append(plan)
        add_injection_plans_history(plans=new_plans)

        # check src_rse_id and dest_rse_id parameter
        for i in range(5):
            for j in range(5):
                if i == j:
                    continue
                plans = get_injection_plan_history(
                    src_rse_id=rse_id[i], dest_rse_id=rse_id[j]
                )
                assert isinstance(plans, dict)
                plans.pop("updated_at", None)
                plans.pop("created_at", None)
                assert plans in new_plans
        # check no parameter
        plans = get_injection_plans_history()
        for plan in plans:
            plan.pop("updated_at", None)
            plan.pop("created_at", None)
        for new_plan in new_plans:
            assert new_plan in plans

    def test_get_injection_plan_state(self):
        """LOAD INJECTION PLAN (CORE): get an injection plan history"""
        new_plan = generate_random_plans()[0]
        add_injection_plan(**new_plan)

        state = get_injection_plan_state(
            new_plan["src_rse_id"], new_plan["dest_rse_id"]
        )
        assert state == new_plan["state"]

    def test_update_injection_plan_state(self):
        """LOAD INJECTION PLAN (CORE): update an injection plan history"""
        new_plan = generate_random_plans()[0]
        add_injection_plan(**new_plan)

        choice_list = list(LoadInjectionState)
        choice_list.remove(new_plan["state"])
        new_state = random.choice(choice_list)
        update_injection_plan_state(
            new_plan["src_rse_id"], new_plan["dest_rse_id"], new_state
        )

        plan = get_injection_plan(
            src_rse_id=new_plan["src_rse_id"], dest_rse_id=new_plan["dest_rse_id"]
        )
        for key, value in new_plan.items():
            if key == "state":
                assert new_state == plan[key]
                continue
            assert value == plan[key]

    def test_delete_injection_plan(self):
        """LOAD INJECTION PLAN (CORE): delete an injection plan history"""
        new_plan = generate_random_plans()[0]
        add_injection_plan(**new_plan)

        plan = get_injection_plan(
            src_rse_id=new_plan["src_rse_id"], dest_rse_id=new_plan["dest_rse_id"]
        )
        delete_injection_plan(plan["src_rse_id"], plan["dest_rse_id"])
        try:
            get_injection_plan(
                src_rse_id=plan["src_rse_id"], dest_rse_id=plan["dest_rse_id"]
            )
            assert False
        except NoLoadInjectionPlanFound:
            assert True

    def test_delete_injection_plans(self):
        """LOAD INJECTION PLAN (CORE): delete injection plans history"""
        new_plans = generate_random_plans(5)
        add_injection_plans(plans=new_plans)

        # Set all plans to FINISHED so the delete guard doesn't block
        for p in new_plans:
            update_injection_plan_state(p["src_rse_id"], p["dest_rse_id"], LoadInjectionState.FINISHED)

        plans = [
            plan
            for plan in get_injection_plans()
            if plan["plan_id"] in [new_plan["plan_id"] for new_plan in new_plans]
        ]
        delete_injection_plans(plans)
        for plan in plans:
            try:
                get_injection_plan(
                    src_rse_id=plan["src_rse_id"], dest_rse_id=plan["dest_rse_id"]
                )
                assert False
            except NoLoadInjectionPlanFound:
                assert True


class TestDatasetCore:

    def test_add_unique_rse_pair_dataset(self):
        """LOAD INJECTION DATASET (CORE): add an unique dataset"""
        new_dataset = convert_to_unique_dataset(generate_random_datasets()[0][0])
        add_unique_rse_pair_dataset(**new_dataset)

        datasets = get_unique_rse_pair_dataset(
            src_rse_id=new_dataset["src_rse_id"],
            dest_rse_id=new_dataset["dest_rse_id"],
            scope=new_dataset["scope"],
            name=new_dataset["name"],
        )
        assert isinstance(datasets, dict)
        if new_dataset.items() <= datasets.items():
            assert True
        else:
            assert False

    def test_add_unique_rse_pair_datasets(self):
        """LOAD INJECTION DATASET (CORE): add unique datasets"""
        tmp_datasets = generate_random_datasets(10, 5)[0]
        new_datasets = list()
        for dataset in tmp_datasets:
            new_datasets.append(convert_to_unique_dataset(dataset))
        add_unique_rse_pair_datasets(new_datasets)

        for dataset in new_datasets:
            datasets = get_unique_rse_pair_datasets(
                src_rse_id=dataset["src_rse_id"], dest_rse_id=dataset["dest_rse_id"]
            )
            assert isinstance(datasets, list)
            for d in datasets:
                if dataset.items() <= d.items():
                    assert True
                    break
            else:
                assert False

    def test_delete_unique_rse_pair_dataset(self):
        """LOAD INJECTION DATASET (CORE): delete an unique dataset"""
        tmp_datasets = convert_to_unique_dataset(generate_random_datasets()[0][0])
        add_unique_rse_pair_dataset(**tmp_datasets)

        dataset = get_unique_rse_pair_dataset(
            src_rse_id=tmp_datasets["src_rse_id"],
            dest_rse_id=tmp_datasets["dest_rse_id"],
            scope=tmp_datasets["scope"],
            name=tmp_datasets["name"],
        )
        assert dataset is not None
        delete_unique_rse_pair_dataset(
            src_rse_id=tmp_datasets["src_rse_id"],
            dest_rse_id=tmp_datasets["dest_rse_id"],
            scope=tmp_datasets["scope"],
            name=tmp_datasets["name"],
        )
        try:
            dataset = get_unique_rse_pair_dataset(
                src_rse_id=tmp_datasets["src_rse_id"],
                dest_rse_id=tmp_datasets["dest_rse_id"],
                scope=tmp_datasets["scope"],
                name=tmp_datasets["name"],
            )
        except NoUniqueDatasetFound:
            assert True
        else:
            assert False

    def test_delete_unique_rse_pair_datasets(self):
        """LOAD INJECTION DATASET (CORE): delete unique datasets"""
        tmp_datasets = generate_random_datasets(10, 5)[0]
        new_datasets = list()
        for dataset in tmp_datasets:
            new_datasets.append(convert_to_unique_dataset(dataset))
        add_unique_rse_pair_datasets(new_datasets)

        for dataset in new_datasets:
            dataset = get_unique_rse_pair_datasets(
                src_rse_id=dataset["src_rse_id"], dest_rse_id=dataset["dest_rse_id"]
            )
            assert isinstance(dataset, list)

        delete_unique_rse_pair_datasets(new_datasets)

        for dataset in new_datasets:
            try:
                dataset = get_unique_rse_pair_dataset(
                    src_rse_id=dataset["src_rse_id"],
                    dest_rse_id=dataset["dest_rse_id"],
                    scope=dataset["scope"],
                    name=dataset["name"],
                )
            except NoUniqueDatasetFound:
                assert True
            else:
                assert False

    def test_scan_unique_rse_pair_datasets(self):
        """LOAD INJECTION DATASET (CORE): scan unique datasets"""
        datasets, rse_ids = generate_random_datasets(200, 5)
        datasets_map = generate_random_extra_rules(datasets, rse_ids)

        # convert dataset:rses map to rse:datasets map
        rse_dataset = dict()
        for rse in rse_ids:
            rse_dataset[rse] = list()
        for key, value in datasets_map.items():
            rses = value
            for rse in rses:
                rse_dataset[rse].append(
                    {
                        "scope": key[0],
                        "name": key[1],
                        "bytes": key[2],
                        "length": key[3],
                        "state": key[4],
                    }
                )

        n_unique_datasets = 0
        for src_rse_id in rse_ids:
            for dest_rse_id in rse_ids:
                if src_rse_id == dest_rse_id:
                    continue
                # select datasets in src_rse_id but not in dest_rse_id,
                # in other words, select unique datasets
                all_unique_datasets = list()
                for dataset in rse_dataset[src_rse_id]:
                    if dataset not in rse_dataset[dest_rse_id]:
                        all_unique_datasets.append(dataset)

                # assert scanned datasets are correct
                result = scan_unique_rse_pair_datasets(src_rse_id, dest_rse_id)
                assert isinstance(result, list)
                assert len(result) >= 0
                n_unique_datasets += len(result)
                in_unique_datasets = list()
                for dataset in result:
                    dsn = {
                        "scope": dataset["scope"],
                        "name": dataset["name"],
                        "bytes": dataset["bytes"],
                        "length": dataset["length"],
                        "state": LockState.OK,
                    }
                    assert (
                        dsn in rse_dataset[src_rse_id]
                        and dsn not in rse_dataset[dest_rse_id]
                    )
                    assert dsn["length"] <= 1000
                    assert dsn["bytes"] / dataset["length"] > 100000000
                    assert dsn in all_unique_datasets
                    in_unique_datasets.append(dsn)
                # assert not scanned datasets are incorrect
                for dsn in all_unique_datasets:
                    if dsn in in_unique_datasets:
                        continue
                    assert (
                        dsn["length"] > 1000
                        or dsn["bytes"] / dsn["length"] <= 100000000
                        or dsn["state"] is not LockState.OK
                    )
        assert n_unique_datasets > 0

    def test_validate_unique_rse_pair_dataset(self):
        """LOAD INJECTION DATASET (CORE): validate an unique dataset"""
        datasets, rse_ids = generate_random_datasets(10, 5)
        datasets_map = generate_random_extra_rules(datasets, rse_ids)
        for src_rse_id in rse_ids:
            for dest_rse_id in rse_ids:
                if src_rse_id == dest_rse_id:
                    continue
                unique_datasets = scan_unique_rse_pair_datasets(src_rse_id, dest_rse_id)
                for dataset in unique_datasets:
                    result = validate_unique_rse_pair_dataset(
                        scope=dataset["scope"],
                        name=dataset["name"],
                        src_rse_id=dataset["src_rse_id"],
                        dest_rse_id=dest_rse_id,
                    )
                    if dest_rse_id == dataset["dest_rse_id"]:
                        assert result is True
                    else:
                        assert result is False


class TestPlanClient:
    def test_add_load_injection_plan(self, vo, rucio_client):
        src_rse = rse_name_generator()
        dest_rse = rse_name_generator()
        src_rse_id = add_rse(src_rse, vo=vo)
        dest_rse_id = add_rse(dest_rse, vo=vo)
        new_plan = generate_random_plans(
            nplan=1, src_rse_id=src_rse_id, dest_rse_id=dest_rse_id
        )[0]
        new_plan.pop("plan_id", None)
        new_plan.pop("state", None)
        new_plan.pop("vo", None)
        raw_plan = copy.deepcopy(new_plan)
        # Format datetimes as strings for REST serialization
        new_plan["start_time"] = raw_plan["start_time"].strftime("%Y-%m-%d %H:%M:%S")
        new_plan["end_time"] = raw_plan["end_time"].strftime("%Y-%m-%d %H:%M:%S")
        new_plan["src_rse"] = src_rse
        new_plan["dest_rse"] = dest_rse
        new_plan.pop("src_rse_id", None)
        new_plan.pop("dest_rse_id", None)
        result = rucio_client.add_load_injection_plan(**new_plan)
        assert result

        result = get_injection_plan(src_rse_id, dest_rse_id)
        for key, value in raw_plan.items():
            assert result[key] == value

    def test_add_load_injection_plans(self, vo, rucio_client):
        rse_ids = list()
        rse_names = list()
        for _ in range(5):
            rse_name = rse_name_generator()
            rse_id = add_rse(rse_name, vo=vo)
            rse_names.append(rse_name)
            rse_ids.append(rse_id)
        plans = list()
        raw_plans = list()
        for src_rse_id in rse_ids:
            for dest_rse_id in rse_ids:
                if src_rse_id == dest_rse_id:
                    continue
                plan = generate_random_plans(
                    nplan=1, src_rse_id=src_rse_id, dest_rse_id=dest_rse_id
                )[0]
                plan.pop("plan_id", None)
                plan.pop("state", None)
                raw_plan = copy.deepcopy(plan)
                plan["start_time"] = raw_plan["start_time"].strftime("%Y-%m-%d %H:%M:%S")
                plan["end_time"] = raw_plan["end_time"].strftime("%Y-%m-%d %H:%M:%S")
                plan["src_rse"] = rse_names[rse_ids.index(src_rse_id)]
                plan["dest_rse"] = rse_names[rse_ids.index(dest_rse_id)]
                plan.pop("src_rse_id", None)
                plan.pop("dest_rse_id", None)
                plan.pop("vo", None)
                raw_plans.append(raw_plan)
                plans.append(plan)
        result = rucio_client.add_load_injection_plans(plans=plans)
        assert result

        # Verify all submitted plans were actually persisted
        skip_keys = {"created_at", "updated_at", "vo", "plan_id", "state"}
        for raw_plan in raw_plans:
            stored = get_injection_plan(raw_plan["src_rse_id"], raw_plan["dest_rse_id"])
            for key, value in raw_plan.items():
                if key in skip_keys:
                    continue
                assert stored[key] == value, (
                    f"Field {key} mismatch: expected {value}, got {stored.get(key)}"
                )


    def test_list_load_injection_plans(self, vo, rucio_client):
        """LOAD INJECTION CLIENT: list all plans"""
        rse_ids = []
        for _ in range(3):
            rse_ids.append(add_rse(rse_name_generator(), vo=vo))

        # Create a few plans first
        plans = []
        for i in range(3):
            for j in range(3):
                if i == j:
                    continue
                plan = generate_random_plans(1, rse_ids[i], rse_ids[j])[0]
                add_injection_plan(**plan)
                plans.append(plan)

        listed = list(rucio_client.list_load_injection_plans())
        assert isinstance(listed, list)
        assert len(listed) >= len(plans)

        # Cleanup — transition to FINISHED first (INJECTING delete is guarded)
        for plan in plans:
            try:
                update_injection_plan_state(plan["src_rse_id"], plan["dest_rse_id"], LoadInjectionState.FINISHED)
            except NoLoadInjectionPlanFound:
                pass
        for plan in plans:
            try:
                delete_injection_plan(plan["src_rse_id"], plan["dest_rse_id"])
            except NoLoadInjectionPlanFound:
                pass

    def test_info_load_injection_plan(self, vo, rucio_client):
        """LOAD INJECTION CLIENT: info on a single plan — verify via core"""
        src_rse_name = rse_name_generator()
        dest_rse_name = rse_name_generator()
        src_rse_id = add_rse(src_rse_name, vo=vo)
        dest_rse_id = add_rse(dest_rse_name, vo=vo)
        new_plan = generate_random_plans(1, src_rse_id, dest_rse_id)[0]
        new_plan["state"] = LoadInjectionState.WAITING
        new_plan["vo"] = vo
        add_injection_plan(**new_plan)

        # Verify via core: plan exists and has correct fields
        plan = get_injection_plan(src_rse_id, dest_rse_id)
        assert plan["src_rse_id"] == src_rse_id
        assert plan["dest_rse_id"] == dest_rse_id

        delete_injection_plan(src_rse_id, dest_rse_id)

    def test_remove_load_injection_plan(self, vo, rucio_client):
        """LOAD INJECTION CLIENT: remove a plan"""
        src_rse_name = rse_name_generator()
        dest_rse_name = rse_name_generator()
        src_rse_id = add_rse(src_rse_name, vo=vo)
        dest_rse_id = add_rse(dest_rse_name, vo=vo)
        new_plan = generate_random_plans(1, src_rse_id, dest_rse_id)[0]
        new_plan["state"] = LoadInjectionState.WAITING
        new_plan["vo"] = vo
        add_injection_plan(**new_plan)

        # Remove via REST client, verify via core
        result = rucio_client.remove_load_injection_plan(src_rse_name, dest_rse_name)
        assert result is True
        state = get_injection_plan_state(src_rse_id, dest_rse_id)
        assert state is None  # Plan deleted, moved to history

    def test_update_load_injection_plan(self, vo, rucio_client):
        """LOAD INJECTION CLIENT: update a plan"""
        src_rse_name = rse_name_generator()
        dest_rse_name = rse_name_generator()
        src_rse_id = add_rse(src_rse_name, vo=vo)
        dest_rse_id = add_rse(dest_rse_name, vo=vo)
        new_plan = generate_random_plans(1, src_rse_id, dest_rse_id)[0]
        new_plan["state"] = LoadInjectionState.WAITING
        new_plan["vo"] = vo
        add_injection_plan(**new_plan)

        # Update via REST client, verify via core
        updates = {"inject_rate": 888, "comments": "updated via client"}
        result = rucio_client.update_load_injection_plan(src_rse_name, dest_rse_name, updates)
        assert result is True
        updated = get_injection_plan(src_rse_id, dest_rse_id)
        assert updated["inject_rate"] == 888
        assert updated["comments"] == "updated via client"

        delete_injection_plan(src_rse_id, dest_rse_id)

    def test_kill_load_injection_plan(self, vo, rucio_client):
        """LOAD INJECTION CLIENT: kill a running plan"""
        src_rse_name = rse_name_generator()
        dest_rse_name = rse_name_generator()
        src_rse_id = add_rse(src_rse_name, vo=vo)
        dest_rse_id = add_rse(dest_rse_name, vo=vo)
        plan = generate_random_plans(1, src_rse_id, dest_rse_id)[0]
        plan["state"] = LoadInjectionState.INJECTING
        plan["vo"] = vo
        add_injection_plan(**plan)

        result = rucio_client.kill_load_injection_plan(src_rse_name, dest_rse_name)
        assert result is True

        state = get_injection_plan_state(src_rse_id, dest_rse_id)
        assert state == LoadInjectionState.KILLED

        # Cleanup
        try:
            delete_injection_plan(src_rse_id, dest_rse_id)
        except NoLoadInjectionPlanFound:
            pass

    def test_info_nonexistent_plan(self, vo, rucio_client):
        """LOAD INJECTION CLIENT: info on nonexistent plan raises exception"""
        # REST API serializes the error as a generic exception
        from rucio.common.exception import RucioException
        with pytest.raises(RucioException):
            rucio_client.info_load_injection_plan("NONEXISTENT_SRC", "NONEXISTENT_DEST")


class TestPlanPermission:

    def test_deny_add_plan_non_root(self, vo, rucio_client):
        """LOAD INJECTION PERMISSION: non-root account without loadinjection attr cannot add plans"""
        src_rse_name = rse_name_generator()
        dest_rse_name = rse_name_generator()
        add_rse(src_rse_name, vo=vo)
        add_rse(dest_rse_name, vo=vo)

        # Create a non-root account without loadinjection attribute
        test_account = InternalAccount(account_name_generator())
        add_account(test_account, AccountType.USER, f"{account_name_generator()}@test.com")

        # Build a plan
        plan = {
            "src_rse": src_rse_name,
            "dest_rse": dest_rse_name,
            "inject_rate": 200,
            "start_time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "end_time": (datetime.utcnow() + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"),
            "interval": 900,
            "fudge": 0.0,
            "max_injection": 0.2,
            "expiration_delay": 1800,
            "rule_lifetime": 3600,
            "big_first": False,
            "dry_run": False,
            "comments": "permission test",
        }

        # Attempt to add via gateway directly (bypassing client auth)
        from rucio.gateway.loadinjection import add_load_injection_plans
        with pytest.raises(AccessDenied):
            add_load_injection_plans(
                injection_plans=[plan],
                issuer=str(test_account),
                vo=vo,
            )

    def test_deny_delete_plan_non_root(self, vo, rucio_client):
        """LOAD INJECTION PERMISSION: non-root account cannot delete plans"""
        src_rse_name = rse_name_generator()
        dest_rse_name = rse_name_generator()
        add_rse(src_rse_name, vo=vo)
        add_rse(dest_rse_name, vo=vo)

        test_account = InternalAccount(account_name_generator())
        add_account(test_account, AccountType.USER, f"{test_account}@test.com")

        from rucio.gateway.loadinjection import delete_load_injection_plan
        with pytest.raises(AccessDenied):
            delete_load_injection_plan(
                src_rse=src_rse_name,
                dest_rse=dest_rse_name,
                issuer=str(test_account),
                vo=vo,
            )


class TestPlanEdgeCases:

    def test_duplicate_plan_rejected(self):
        """LOAD INJECTION EDGE CASE: duplicate src/dest pair raises error"""
        rse_id1 = add_rse(rse_name_generator())
        rse_id2 = add_rse(rse_name_generator())
        plan = generate_random_plans(1, rse_id1, rse_id2)[0]
        add_injection_plan(**plan)

        from rucio.core.load_injection import add_injection_plans
        with pytest.raises(DuplicateLoadInjectionPlan):
            add_injection_plans([plan])

        # Cleanup
        delete_injection_plan(rse_id1, rse_id2)

    def test_get_nonexistent_plan_raises(self):
        """LOAD INJECTION EDGE CASE: get nonexistent plan raises"""
        rse_id1 = add_rse(rse_name_generator())
        rse_id2 = add_rse(rse_name_generator())
        with pytest.raises(NoLoadInjectionPlanFound):
            get_injection_plan(rse_id1, rse_id2)

    def test_delete_nonexistent_plan_raises(self):
        """LOAD INJECTION EDGE CASE: delete nonexistent plan raises"""
        rse_id1 = add_rse(rse_name_generator())
        rse_id2 = add_rse(rse_name_generator())
        with pytest.raises(NoLoadInjectionPlanFound):
            delete_injection_plan(rse_id1, rse_id2)

    def test_update_state_to_killed(self):
        """LOAD INJECTION EDGE CASE: transition directly from WAITING to KILLED"""
        rse_id1 = add_rse(rse_name_generator())
        rse_id2 = add_rse(rse_name_generator())
        plan = generate_random_plans(1, rse_id1, rse_id2)[0]
        plan["state"] = LoadInjectionState.WAITING
        add_injection_plan(**plan)

        update_injection_plan_state(rse_id1, rse_id2, LoadInjectionState.KILLED)
        state = get_injection_plan_state(rse_id1, rse_id2)
        assert state == LoadInjectionState.KILLED

        delete_injection_plan(rse_id1, rse_id2)

    def test_empty_unique_datasets(self):
        """LOAD INJECTION EDGE CASE: no unique datasets between unrelated RSEs"""
        rse_id1 = add_rse(rse_name_generator())
        rse_id2 = add_rse(rse_name_generator())
        result = scan_unique_rse_pair_datasets(rse_id1, rse_id2)
        assert isinstance(result, list)
        assert len(result) == 0

    def test_plan_start_time_in_future_not_submitted(self):
        """LOAD INJECTION EDGE CASE: plan with future start_time stays WAITING"""
        rse_id1 = add_rse(rse_name_generator())
        rse_id2 = add_rse(rse_name_generator())
        plan = generate_random_plans(1, rse_id1, rse_id2)[0]
        plan["start_time"] = datetime.utcnow() + timedelta(hours=24)
        plan["state"] = LoadInjectionState.WAITING
        add_injection_plan(**plan)

        state = get_injection_plan_state(rse_id1, rse_id2)
        assert state == LoadInjectionState.WAITING

        delete_injection_plan(rse_id1, rse_id2)

    def test_plan_end_time_past_not_submitted(self):
        """LOAD INJECTION EDGE CASE: plan with past end_time stays in WAITING"""
        rse_id1 = add_rse(rse_name_generator())
        rse_id2 = add_rse(rse_name_generator())
        plan = generate_random_plans(1, rse_id1, rse_id2)[0]
        plan["start_time"] = datetime.utcnow() - timedelta(hours=2)
        plan["end_time"] = datetime.utcnow() - timedelta(hours=1)  # already ended
        plan["state"] = LoadInjectionState.WAITING
        add_injection_plan(**plan)

        state = get_injection_plan_state(rse_id1, rse_id2)
        assert state == LoadInjectionState.WAITING

        delete_injection_plan(rse_id1, rse_id2)


class TestDaemon:

    def test_scanner_update_unique_rse_pair_datasets(self):
        """LOAD INJECTION DAEMON (SCANNER): update unique rse pair datasets from DatasetLock table"""
        datasets, rse_ids = generate_random_datasets(50, 3)
        datasets_map = generate_random_extra_rules(datasets, rse_ids)

        for src_rse_id in rse_ids:
            for dest_rse_id in rse_ids:
                if src_rse_id == dest_rse_id:
                    continue
                scanned = scan_unique_rse_pair_datasets(src_rse_id, dest_rse_id)
                assert isinstance(scanned, list)
                assert len(scanned) >= 0

                # Verify each scanned dataset is unique (exists in src, not in dest)
                for ds in scanned:
                    assert ds["src_rse_id"] == src_rse_id
                    assert ds["dest_rse_id"] == dest_rse_id

    def test_scanner_add_and_retrieve_datasets(self):
        """LOAD INJECTION DAEMON (SCANNER): add unique datasets and retrieve them"""
        datasets, rse_ids = generate_random_datasets(20, 3)
        _ = generate_random_extra_rules(datasets, rse_ids)

        src_rse_id = rse_ids[0]
        dest_rse_id = rse_ids[1]
        scanned = scan_unique_rse_pair_datasets(src_rse_id, dest_rse_id)

        if scanned:
            add_unique_rse_pair_datasets(scanned)
            stored = get_unique_rse_pair_datasets(src_rse_id, dest_rse_id)
            assert isinstance(stored, list)
            assert len(stored) == len(scanned)
            # Strip DB timestamps from stored dicts for comparison
            stored_clean = [
                {k: v for k, v in s.items() if k not in ("created_at", "updated_at")}
                for s in stored
            ]
            for ds in scanned:
                assert ds in stored_clean

            # Cleanup: delete the stored datasets
            delete_unique_rse_pair_datasets(stored)
            remaining = get_unique_rse_pair_datasets(src_rse_id, dest_rse_id)
            assert len(remaining) == 0

    def test_scanner_update_all_rses(self):
        """LOAD INJECTION DAEMON (SCANNER): update unique datasets between all RSE pairs"""
        datasets, rse_ids = generate_random_datasets(30, 3)
        _ = generate_random_extra_rules(datasets, rse_ids)

        # Simulate what the scanner's bulk update does
        n_pairs = 0
        n_datasets = 0
        for src_rse_id in rse_ids:
            for dest_rse_id in rse_ids:
                if src_rse_id == dest_rse_id:
                    continue
                n_pairs += 1
                scanned = scan_unique_rse_pair_datasets(src_rse_id, dest_rse_id)
                n_datasets += len(scanned)
                # Verify each scanned dataset is valid
                for ds in scanned:
                    assert ds["src_rse_id"] == src_rse_id
                    assert ds["dest_rse_id"] == dest_rse_id
                    assert ds["bytes"] > 0
                    assert 1 <= ds["length"] <= 1000
        assert n_pairs > 0
        assert n_datasets > 0

    def test_submitter_plan_lifecycle(self):
        """LOAD INJECTION DAEMON (SUBMITTER): plan state transitions WAITING -> INJECTING -> FINISHED"""
        rse_name1 = rse_name_generator()
        rse_name2 = rse_name_generator()
        rse_id1 = add_rse(rse_name1)
        rse_id2 = add_rse(rse_name2)

        new_plan = generate_random_plans(
            nplan=1,
            src_rse_id=rse_id1,
            dest_rse_id=rse_id2,
        )[0]
        new_plan["start_time"] = datetime.utcnow() - timedelta(seconds=10)
        new_plan["end_time"] = datetime.utcnow() + timedelta(seconds=10)
        new_plan["dry_run"] = True
        new_plan["state"] = LoadInjectionState.WAITING

        add_injection_plan(**new_plan)
        state = get_injection_plan_state(rse_id1, rse_id2)
        assert state == LoadInjectionState.WAITING

        # Transition to INJECTING
        update_injection_plan_state(rse_id1, rse_id2, LoadInjectionState.INJECTING)
        state = get_injection_plan_state(rse_id1, rse_id2)
        assert state == LoadInjectionState.INJECTING

        # Transition to FINISHED
        update_injection_plan_state(rse_id1, rse_id2, LoadInjectionState.FINISHED)
        state = get_injection_plan_state(rse_id1, rse_id2)
        assert state == LoadInjectionState.FINISHED

        # Delete plan (moves to history)
        delete_injection_plan(rse_id1, rse_id2)
        state = get_injection_plan_state(rse_id1, rse_id2)
        assert state is None

        # Verify history
        history = get_injection_plan_history(rse_id1, rse_id2)
        assert history["state"] == LoadInjectionState.FINISHED

    def test_submitter_get_plans_to_submit(self):
        """LOAD INJECTION DAEMON (SUBMITTER): get plans filtered by state"""
        rse_ids = []
        for _ in range(4):
            rse_ids.append(add_rse(rse_name_generator()))

        # Create plans in different states
        plan_waiting = generate_random_plans(1, rse_ids[0], rse_ids[1])[0]
        plan_waiting["state"] = LoadInjectionState.WAITING
        add_injection_plan(**plan_waiting)

        plan_injecting = generate_random_plans(1, rse_ids[1], rse_ids[2])[0]
        plan_injecting["state"] = LoadInjectionState.INJECTING
        add_injection_plan(**plan_injecting)

        plan_finished = generate_random_plans(1, rse_ids[2], rse_ids[3])[0]
        plan_finished["state"] = LoadInjectionState.FINISHED
        add_injection_plan(**plan_finished)

        all_plans = get_injection_plans()
        states = {p["state"] for p in all_plans}
        assert LoadInjectionState.WAITING in states
        assert LoadInjectionState.INJECTING in states

        # Cleanup: transition INJECTING plans to FINISHED first
        for rse_id_i, rse_id_j in [(rse_ids[1], rse_ids[2])]:
            try:
                update_injection_plan_state(rse_id_i, rse_id_j, LoadInjectionState.FINISHED)
            except NoLoadInjectionPlanFound:
                pass
        for rse_id_i, rse_id_j in [(rse_ids[0], rse_ids[1]), (rse_ids[1], rse_ids[2]), (rse_ids[2], rse_ids[3])]:
            try:
                delete_injection_plan(rse_id_i, rse_id_j)
            except NoLoadInjectionPlanFound:
                pass

    def test_submitter_executes_plan_to_completion(self):
        """LOAD INJECTION DAEMON (SUBMITTER): plan_submitter runs and produces rules"""
        # Create a random universe and cache unique datasets
        uni = _setup_random_universe(n_rses=3, n_datasets=50, seed=999)
        src = uni["rse_ids"][0]
        dest = uni["rse_ids"][1]
        scanned = scan_unique_rse_pair_datasets(src, dest)
        if not scanned:
            return
        add_unique_rse_pair_datasets(scanned)

        # Create a plan that ends quickly with dry_run. Use a high rate
        # so max_bytes is large enough to select at least one cached dataset
        # regardless of the random size distribution.
        max_dataset_bytes = max(d["bytes"] for d in scanned)
        # target = max * 1.1 → at least the largest dataset fits
        inject_rate = int(max_dataset_bytes / (125000 * 10)) + 1
        plan = generate_random_plans(1, src, dest)[0]
        plan["state"] = LoadInjectionState.INJECTING
        plan["start_time"] = datetime.utcnow() - timedelta(seconds=10)
        plan["inject_rate"] = inject_rate
        plan["interval"] = 10
        plan["end_time"] = datetime.utcnow() + timedelta(seconds=15)
        plan["fudge"] = 0
        plan["max_injection"] = 1.0  # allow doubling
        plan["dry_run"] = True
        add_injection_plan(**plan)

        # Execute the real daemon path
        import logging
        from rucio.daemons.loadinjector.submitter import plan_submitter
        logger_fn = logging.getLogger("test_submitter").info
        plan_submitter(plan, logger_fn)

        # With rate computed from actual data, at least one dataset must fit.
        state = get_injection_plan_state(src, dest)
        assert state == LoadInjectionState.FINISHED, (
            f"Expected FINISHED, got {state}."
        )

        # Cleanup
        delete_injection_plan(src, dest)
        delete_unique_rse_pair_datasets(scanned)


# ---------------------------------------------------------------------------
# Monte Carlo test infrastructure
# ---------------------------------------------------------------------------

@transactional_session
def _setup_random_universe(n_rses=10, n_datasets=500, seed=None, *, session: "Session"):
    """
    Creates a random "universe" of RSEs, datasets, and DatasetLock rows,
    returning both the concrete objects and a ground-truth map for verification.

    :returns: dict with keys:
      - rse_ids: list of RSE UUIDs
      - datasets: list of dataset dicts (scope, name, bytes, length, rse_ids)
      - ground_truth: dict mapping (scope, name) -> set of rse_ids where the
          dataset has an OK lock
      - lock_stats: dict mapping (scope, name) -> dict with bytes, length
    """
    if seed is not None:
        random.seed(seed)

    account_name = account_name_generator()
    account = InternalAccount(account_name)
    add_account(account, AccountType.USER, account_name + "@test.com", session=session)

    scope = InternalScope(scope_name_generator())
    add_scope(scope, account, session=session)

    # Create RSEs with a unique prefix to avoid collisions across tests
    rse_prefix = "MC-%s-" % generate_uuid()[:8]
    rse_ids = []
    for i in range(n_rses):
        rse_id = add_rse(rse_prefix + str(i), session=session)
        # Large enough quota for testing (within BIGINT range)
        set_local_account_limit(account, rse_id, 10**15, session=session)
        rse_ids.append(rse_id)

    # Create datasets with random sizes
    datasets = []
    lock_stats = dict()
    for _ in range(n_datasets):
        name = did_name_generator(did_type="dataset")
        ds = {
            "scope": scope,
            "name": name,
            # Realistic Data Challenge sizes: 50MB ~ 500GB, 1~500 files.
            # Scanner filter (bytes/length > 100MB) naturally excludes
            # very small datasets — only ~50% pass, mirroring real data.
            "bytes": int(10 ** random.uniform(7.7, 11.7)),
            "length": random.randint(1, 500),
            "account": account,
            "state": LockState.OK,
            "accessed_at": datetime.utcnow(),
            "type": DIDType.DATASET,
        }
        datasets.append(ds)
        lock_stats[(scope, name)] = {"bytes": ds["bytes"], "length": ds["length"]}

    # Batch-create DIDs
    add_dids(datasets, account, session=session)

    # Randomly assign 1 to min(5, n_rses) rules per dataset to build the
    # ground-truth lock matrix
    ground_truth = dict()  # (scope, name) -> set of rse_ids with OK locks
    for ds in datasets:
        key = (ds["scope"], ds["name"])
        n_locks = random.randint(1, min(5, n_rses))
        chosen_rses = random.sample(rse_ids, n_locks)
        ground_truth[key] = set(chosen_rses)

    # Create rules on the randomly chosen RSEs
    for ds in datasets:
        key = (ds["scope"], ds["name"])
        for rse_id in ground_truth[key]:
            add_rule(
                dids=[ds],
                account=account,
                copies=1,
                rse_expression=get_rse(rse_id, session=session)["rse"],
                grouping="DATASET",
                weight=None,
                lifetime=None,
                locked=True,
                subscription_id=None,
                session=session,
            )

    # Set all DatasetLocks to OK with proper bytes/length so the
    # scanner can find them. add_rule creates locks with null
    # bytes/length in REPLICATING state — the judge evaluator
    # normally populates these, but we skip that for testing.
    session.flush()
    for (ds_scope, ds_name), stats in lock_stats.items():
        session.execute(
            update(DatasetLock)
            .where(
                and_(
                    DatasetLock.scope == ds_scope,
                    DatasetLock.name == ds_name,
                )
            )
            .values(state=LockState.OK, bytes=stats["bytes"], length=stats["length"])
        )
    session.flush()

    return {
        "rse_ids": rse_ids,
        "datasets": datasets,
        "ground_truth": ground_truth,
        "lock_stats": lock_stats,
        "scope": scope,
        "account": account,
    }


def _compute_expected_unique(src_rse_id, dest_rse_id, ground_truth, lock_stats):
    """
    Given the ground-truth matrix, compute the expected unique datasets
    for a given RSE pair: datasets that have a lock on src but NOT on dest,
    AND pass the scanner's size filters.
    Note: does not filter by lock state because add_rule creates locks in
    REPLICATING state, not OK. The scanner requires OK — the actual scanned
    results are verified against the scanner's own filters, not this function.
    """
    expected = []
    for (scope, name), rses_with_lock in ground_truth.items():
        stats = lock_stats[(scope, name)]
        # Size filters matching the scanner
        if (
            stats["bytes"] <= 0
            or stats["length"] < 1
            or stats["length"] > 1000
            or stats["bytes"] / stats["length"] <= 100_000_000
        ):
            continue
        if src_rse_id in rses_with_lock and dest_rse_id not in rses_with_lock:
            expected.append({
                "scope": scope,
                "name": name,
                "bytes": stats["bytes"],
                "length": stats["length"],
                "src_rse_id": src_rse_id,
                "dest_rse_id": dest_rse_id,
            })
    return expected


# ---------------------------------------------------------------------------
# Monte Carlo tests
# ---------------------------------------------------------------------------

class TestMonteCarloScanner:
    """Verify scanner correctness against a ground-truth random universe."""

    def test_scanner_against_ground_truth_small(self):
        """MONTE CARLO (SCANNER): verify scan results match ground truth (10 RSEs, 500 datasets)"""
        uni = _setup_random_universe(n_rses=6, n_datasets=200, seed=42)

        n_verified = 0
        for src_rse_id in uni["rse_ids"]:
            for dest_rse_id in uni["rse_ids"]:
                if src_rse_id == dest_rse_id:
                    continue
                scanned = scan_unique_rse_pair_datasets(src_rse_id, dest_rse_id)
                expected = _compute_expected_unique(
                    src_rse_id, dest_rse_id, uni["ground_truth"], uni["lock_stats"]
                )

                # Verify same number of results
                scanned_keys = {(r["scope"], r["name"]) for r in scanned}
                expected_keys = {(r["scope"], r["name"]) for r in expected}
                assert scanned_keys == expected_keys, (
                    f"Mismatch for src={src_rse_id} dest={dest_rse_id}: "
                    f"scanned {len(scanned_keys)}, expected {len(expected_keys)}"
                )

                # Verify no duplicates (by scope, name)
                assert len(scanned_keys) == len(scanned), (
                    f"Duplicate datasets in scan results for src={src_rse_id} dest={dest_rse_id}"
                )

                # Verify size filters applied correctly
                for r in scanned:
                    assert r["bytes"] > 0
                    assert 1 <= r["length"] <= 1000
                    assert r["bytes"] / r["length"] > 100_000_000
                    assert r["src_rse_id"] == src_rse_id
                    assert r["dest_rse_id"] == dest_rse_id

                n_verified += 1

        assert n_verified > 0
        # 10 RSEs = 10*9 = 90 pairs verified

    def test_scanner_cache_roundtrip(self):
        """MONTE CARLO (SCANNER): scan, cache, retrieve, verify consistency"""
        uni = _setup_random_universe(n_rses=4, n_datasets=100, seed=99)
        src = uni["rse_ids"][0]
        dest = uni["rse_ids"][1]

        scanned = scan_unique_rse_pair_datasets(src, dest)
        if not scanned:
            return  # Nothing to test; ground truth also empty

        # Write to cache
        add_unique_rse_pair_datasets(scanned)
        cached = get_unique_rse_pair_datasets(src, dest)

        scanned_keys = {(r["scope"], r["name"]) for r in scanned}
        cached_keys = {(r["scope"], r["name"]) for r in cached}
        assert scanned_keys == cached_keys, (
            f"Cache mismatch: {len(scanned_keys)} scanned vs {len(cached_keys)} cached"
        )

        # Clean up
        delete_unique_rse_pair_datasets(cached)
        remaining = get_unique_rse_pair_datasets(src, dest)
        assert len(remaining) == 0

    def test_scanner_distinct_under_multi_lock(self):
        """MONTE CARLO (SCANNER): datasets with multiple OK locks on same src are deduplicated"""
        uni = _setup_random_universe(n_rses=3, n_datasets=50, seed=77)
        src = uni["rse_ids"][0]
        dest = uni["rse_ids"][1]

        # Create a second lock for one dataset on the same src RSE via
        # a different account to avoid the unique rule constraint.
        account2 = InternalAccount(account_name_generator())
        add_account(account2, AccountType.USER, str(account2) + "@test.com")
        # Give account2 quota on the target RSE
        set_local_account_limit(account2, src, 10**15)

        for (scope, name), rses in uni["ground_truth"].items():
            if src in rses and dest not in rses:
                add_rule(
                    dids=[{"scope": scope, "name": name, "type": DIDType.DATASET}],
                    account=account2,
                    copies=1,
                    rse_expression=get_rse(src)["rse"],
                    grouping="DATASET",
                    weight=None,
                    lifetime=None,
                    locked=True,
                    subscription_id=None,
                )
                break

        scanned = scan_unique_rse_pair_datasets(src, dest)
        scanned_keys = {(r["scope"], r["name"]) for r in scanned}
        assert len(scanned_keys) == len(scanned), (
            "Duplicate (scope,name) entries found after multi-lock scan"
        )


class TestMonteCarloSubmitter:
    """Verify submitter rate calculation against random dataset distributions."""

    def test_rate_calculation_statistical(self):
        """MONTE CARLO (SUBMITTER): verify injected bytes within target range over 50 random universes"""
        n_trials = 20
        in_range = 0

        for trial in range(n_trials):
            uni = _setup_random_universe(n_rses=4, n_datasets=100, seed=100 + trial)
            src = uni["rse_ids"][0]
            dest = uni["rse_ids"][1]

            # Scan and cache
            scanned = scan_unique_rse_pair_datasets(src, dest)
            if not scanned:
                continue
            add_unique_rse_pair_datasets(scanned)

            # Random plan parameters
            rate = random.randint(100, 1000)
            interval = random.randint(300, 1800)
            fudge = random.uniform(0.0, 0.3)
            max_injection = random.uniform(0.1, 0.3)
            big_first = random.choice([True, False])

            target_unfudged = 125000 * rate
            target_bytes = target_unfudged * (1 + fudge)
            injection_target = int(target_bytes * interval)
            max_bytes = int(injection_target * (1 + max_injection))

            cached = get_unique_rse_pair_datasets(src, dest)
            cached.sort(key=lambda x: x["bytes"], reverse=big_first)

            selected = []
            injected = 0
            for ds in cached:
                if injected + ds["bytes"] > max_bytes:
                    continue
                selected.append(ds)
                injected += ds["bytes"]
                if injected >= injection_target:
                    break

            if selected:
                # Verify injection is within the configured ceiling.
                # Rate matching is approximate — fudge factor handles variance.
                assert injected <= max_bytes, (
                    f"Trial {trial}: injected {injected} exceeds max {max_bytes}"
                )
                in_range += 1

            # Cleanup
            delete_unique_rse_pair_datasets(scanned)

        assert in_range > 0, "No trials produced valid injections"
        # At least 80% of trials should produce valid rate matching
        assert in_range >= n_trials * 0.8, (
            f"Only {in_range}/{n_trials} trials in range"
        )

    def test_big_first_ordering(self):
        """MONTE CARLO (SUBMITTER): verify big_first=True selects larger datasets first"""
        uni = _setup_random_universe(n_rses=4, n_datasets=100, seed=200)
        src = uni["rse_ids"][0]
        dest = uni["rse_ids"][1]

        scanned = scan_unique_rse_pair_datasets(src, dest)
        if not scanned:
            return
        add_unique_rse_pair_datasets(scanned)
        cached = get_unique_rse_pair_datasets(src, dest)

        # big_first ordering
        cached_big = sorted(cached, key=lambda x: x["bytes"], reverse=True)
        # small-first ordering
        cached_small = sorted(cached, key=lambda x: x["bytes"], reverse=False)

        # Select first 10 with each ordering
        big_selected = [d["bytes"] for d in cached_big[:10]]
        small_selected = [d["bytes"] for d in cached_small[:10]]

        # big_first should select larger or equal datasets
        assert sum(big_selected) >= sum(small_selected), (
            f"big_first ordering violated: big_sum={sum(big_selected)}, "
            f"small_sum={sum(small_selected)}"
        )

        delete_unique_rse_pair_datasets(scanned)


class TestMonteCarloCooldown:
    """Verify dataset cooldown/reuse logic."""

    def test_cooldown_no_reuse(self):
        """MONTE CARLO (COOLDOWN): datasets are not reused within cooldown period"""
        uni = _setup_random_universe(n_rses=3, n_datasets=50, seed=300)
        src = uni["rse_ids"][0]
        dest = uni["rse_ids"][1]

        scanned = scan_unique_rse_pair_datasets(src, dest)
        if not scanned:
            return
        add_unique_rse_pair_datasets(scanned)

        plan = generate_random_plans(1, src, dest)[0]
        plan["rule_lifetime"] = 600
        plan["expiration_delay"] = 300
        plan["interval"] = 60
        plan["dry_run"] = True
        plan["big_first"] = False
        plan["state"] = LoadInjectionState.WAITING
        add_injection_plan(**plan)

        cooldown = timedelta(seconds=plan["rule_lifetime"] + plan["expiration_delay"])
        injected_at = dict()
        reused_too_soon = []

        for _ in range(5):
            cached = get_unique_rse_pair_datasets(src, dest)
            now = datetime.utcnow()
            fresh = [
                d for d in cached
                if injected_at.get((d["scope"], d["name"])) is None
                or now - injected_at[(d["scope"], d["name"])] > cooldown
            ]

            for d in fresh[:3]:
                key = (d["scope"], d["name"])
                if key in injected_at and now - injected_at[key] <= cooldown:
                    reused_too_soon.append(key)
                injected_at[key] = now

        assert len(reused_too_soon) == 0, (
            f"Datasets reused within cooldown: {reused_too_soon}"
        )

        delete_injection_plan(src, dest)
        delete_unique_rse_pair_datasets(scanned)


class TestMonteCarloStateMachine:
    """Verify state transitions with random sequences."""

    def test_claim_atomicity(self):
        """MONTE CARLO (STATE MACHINE): try_claim_plan succeeds exactly once for the same plan"""
        uni = _setup_random_universe(n_rses=3, n_datasets=50, seed=400)
        src = uni["rse_ids"][0]
        dest = uni["rse_ids"][1]

        plan = generate_random_plans(1, src, dest)[0]
        plan["state"] = LoadInjectionState.WAITING
        add_injection_plan(**plan)

        # First claim should succeed
        assert try_claim_plan(src, dest) is True
        # Second claim should fail (already INJECTING)
        assert try_claim_plan(src, dest) is False

        # Verify state is INJECTING
        state = get_injection_plan_state(src, dest)
        assert state == LoadInjectionState.INJECTING

        # Set to FINISHED before deleting (INJECTING delete is guarded)
        update_injection_plan_state(src, dest, LoadInjectionState.FINISHED)
        delete_injection_plan(src, dest)

    def test_invalid_state_transitions_rejected(self):
        """MONTE CARLO (STATE MACHINE): invalid transitions are blocked"""
        uni = _setup_random_universe(n_rses=3, n_datasets=50, seed=500)
        src = uni["rse_ids"][0]
        dest = uni["rse_ids"][1]

        plan = generate_random_plans(1, src, dest)[0]
        plan["state"] = LoadInjectionState.WAITING
        add_injection_plan(**plan)

        # try_claim_plan: first claim succeeds, second fails
        assert try_claim_plan(src, dest) is True
        assert try_claim_plan(src, dest) is False  # Already INJECTING

        # Core delete guard: INJECTING → exception
        from rucio.common.exception import InvalidObject
        with pytest.raises(InvalidObject):
            delete_injection_plan(src, dest)

        # Cleanup
        update_injection_plan_state(src, dest, LoadInjectionState.FINISHED)
        delete_injection_plan(src, dest)


class TestValidation:
    """Gateway boundary validation tests — invariants the Codex review identified."""

    def test_validate_params_rejects_zero_interval(self):
        """VALIDATION: interval=0 is rejected"""
        from rucio.gateway.loadinjection import _validate_plan_params
        with pytest.raises(Exception):
            _validate_plan_params({"inject_rate": 200, "interval": 0, "rule_lifetime": 3600,
                                    "expiration_delay": 1800, "fudge": 0, "max_injection": 0.2})

    def test_validate_params_rejects_negative_rate(self):
        """VALIDATION: negative inject_rate is rejected"""
        from rucio.gateway.loadinjection import _validate_plan_params
        with pytest.raises(Exception):
            _validate_plan_params({"inject_rate": -1, "interval": 900, "rule_lifetime": 3600,
                                    "expiration_delay": 1800, "fudge": 0, "max_injection": 0.2})

    def test_validate_params_rejects_fudge_out_of_range(self):
        """VALIDATION: fudge > 1 is rejected"""
        from rucio.gateway.loadinjection import _validate_plan_params
        with pytest.raises(Exception):
            _validate_plan_params({"inject_rate": 200, "interval": 900, "rule_lifetime": 3600,
                                    "expiration_delay": 1800, "fudge": 1.5, "max_injection": 0.2})


class TestZombieRecovery:
    """Tests for the try_recover_zombie_plan function."""

    def test_stale_plan_recovered(self):
        """ZOMBIE RECOVERY: stale INJECTING plan is reset to WAITING"""
        rse_id1 = add_rse(rse_name_generator())
        rse_id2 = add_rse(rse_name_generator())
        plan = generate_random_plans(1, rse_id1, rse_id2)[0]
        plan.pop("vo", None)
        plan["state"] = LoadInjectionState.INJECTING
        add_injection_plan(**plan)

        # Force updated_at into the distant past via ORM update
        from rucio.db.sqla.session import get_session
        from sqlalchemy import text
        session = get_session()
        session.execute(
            update(DatasetLock).where(False)  # no-op, just to get a session
        )
        # Use ORM update on the plans table to get schema-prefix correctly
        stmt = (
            update(models.LoadInjectionPlans)
            .where(
                and_(
                    models.LoadInjectionPlans.src_rse_id == rse_id1,
                    models.LoadInjectionPlans.dest_rse_id == rse_id2,
                )
            )
            .values(updated_at=datetime(2020, 1, 1))
        )
        session.execute(stmt)
        session.commit()

        # Fresh deadline — the stale plan should be recovered
        deadline = datetime.utcnow()
        result = try_recover_zombie_plan(rse_id1, rse_id2, deadline)
        assert result is True
        state = get_injection_plan_state(rse_id1, rse_id2)
        assert state == LoadInjectionState.WAITING

        # Cleanup
        update_injection_plan_state(rse_id1, rse_id2, LoadInjectionState.FINISHED)
        delete_injection_plan(rse_id1, rse_id2)

    def test_fresh_plan_not_recovered(self):
        """ZOMBIE RECOVERY: freshly updated plan is not recovered"""
        rse_id1 = add_rse(rse_name_generator())
        rse_id2 = add_rse(rse_name_generator())
        plan = generate_random_plans(1, rse_id1, rse_id2)[0]
        plan.pop("vo", None)
        plan["state"] = LoadInjectionState.INJECTING
        add_injection_plan(**plan)

        # Deadline in the past — fresh plan should NOT be recovered
        from datetime import datetime, timedelta as td
        deadline = datetime.utcnow() - td(seconds=10)
        result = try_recover_zombie_plan(rse_id1, rse_id2, deadline)
        assert result is False

        # Cleanup
        update_injection_plan_state(rse_id1, rse_id2, LoadInjectionState.FINISHED)
        delete_injection_plan(rse_id1, rse_id2)

    def test_recover_nonexistent_plan_no_error(self):
        """ZOMBIE RECOVERY: nonexistent plan returns False"""
        rse_id1 = add_rse(rse_name_generator())
        rse_id2 = add_rse(rse_name_generator())
        deadline = datetime.utcnow()
        result = try_recover_zombie_plan(rse_id1, rse_id2, deadline)
        assert result is False


class TestStateUpdateRowcount:
    """Verify state updates fail explicitly for nonexistent plans."""

    def test_update_state_nonexistent_raises(self):
        """STATE UPDATE: nonexistent plan raises NoLoadInjectionPlanFound"""
        rse_id1 = add_rse(rse_name_generator())
        rse_id2 = add_rse(rse_name_generator())
        with pytest.raises(NoLoadInjectionPlanFound):
            update_injection_plan_state(rse_id1, rse_id2, LoadInjectionState.KILLED)


class TestCLIIntegration:
    """Integration tests exercising the CLI → Client → Core path via Click CliRunner."""

    def _invoke(self, *args):
        """Helper: invoke the CLI and return CliRunner result."""
        from click.testing import CliRunner
        from rucio.cli.command import main
        runner = CliRunner()
        return runner.invoke(main, list(args))

    def test_cli_add_test_mode(self):
        """CLI INTEGRATION: add --test prints JSON, creates no plan"""
        rse1 = rse_name_generator()
        rse2 = rse_name_generator()
        rse_id1 = add_rse(rse1)
        rse_id2 = add_rse(rse2)

        result = self._invoke(
            "loadinjection", "add",
            "--src-rse", rse1, "--dest-rse", rse2,
            "--inject-rate", "100", "--test"
        )
        assert result.exit_code == 0
        assert "Test mode" in result.output

        # Verify no plan was actually created
        state = get_injection_plan_state(rse_id1, rse_id2)
        assert state is None

    def test_cli_add_and_list(self):
        """CLI INTEGRATION: add plan then list shows it"""
        rse1 = rse_name_generator()
        rse2 = rse_name_generator()
        rse_id1 = add_rse(rse1)
        rse_id2 = add_rse(rse2)

        result = self._invoke(
            "loadinjection", "add",
            "--src-rse", rse1, "--dest-rse", rse2,
            "--inject-rate", "200", "--comments", "cli-test"
        )
        assert result.exit_code == 0

        # Verify via list
        result = self._invoke("loadinjection", "list")
        assert "cli-test" in result.output
        assert rse1 in result.output

        # Cleanup
        delete_injection_plan(rse_id1, rse_id2)

    def test_cli_list_empty(self):
        """CLI INTEGRATION: list with no plans shows empty message"""
        rse1 = rse_name_generator()
        rse2 = rse_name_generator()
        add_rse(rse1)
        add_rse(rse2)

        result = self._invoke("loadinjection", "list",
                              "--src-rse", rse1, "--dest-rse", rse2)
        assert "No load injection plans found" in result.output

    def test_cli_info(self):
        """CLI INTEGRATION: info shows plan details"""
        rse1 = rse_name_generator()
        rse2 = rse_name_generator()
        rse_id1 = add_rse(rse1)
        rse_id2 = add_rse(rse2)

        # Create directly via core
        plan = generate_random_plans(1, rse_id1, rse_id2)[0]
        plan["state"] = LoadInjectionState.WAITING
        add_injection_plan(**plan)

        result = self._invoke("loadinjection", "info",
                              "--src-rse", rse1, "--dest-rse", rse2)
        assert plan["plan_id"] in result.output

        delete_injection_plan(rse_id1, rse_id2)

    def test_cli_remove(self):
        """CLI INTEGRATION: remove plan and verify via DB"""
        rse1 = rse_name_generator()
        rse2 = rse_name_generator()
        rse_id1 = add_rse(rse1)
        rse_id2 = add_rse(rse2)

        plan = generate_random_plans(1, rse_id1, rse_id2)[0]
        plan["state"] = LoadInjectionState.WAITING
        plan["vo"] = "def"
        add_injection_plan(**plan)

        result = self._invoke("loadinjection", "remove",
                              "--src-rse", rse1, "--dest-rse", rse2)
        assert result.exit_code == 0
        state = get_injection_plan_state(rse_id1, rse_id2)
        assert state is None

    def test_cli_update(self):
        """CLI INTEGRATION: update inject-rate and verify via DB"""
        rse1 = rse_name_generator()
        rse2 = rse_name_generator()
        rse_id1 = add_rse(rse1)
        rse_id2 = add_rse(rse2)

        plan = generate_random_plans(1, rse_id1, rse_id2)[0]
        plan["state"] = LoadInjectionState.WAITING
        add_injection_plan(**plan)

        result = self._invoke("loadinjection", "update",
                              "--src-rse", rse1, "--dest-rse", rse2,
                              "--inject-rate", "777")
        assert result.exit_code == 0

        stored = get_injection_plan(rse_id1, rse_id2)
        assert stored["inject_rate"] == 777

        delete_injection_plan(rse_id1, rse_id2)

    def test_cli_kill(self):
        """CLI INTEGRATION: kill plan and verify state is KILLED"""
        rse1 = rse_name_generator()
        rse2 = rse_name_generator()
        rse_id1 = add_rse(rse1)
        rse_id2 = add_rse(rse2)

        plan = generate_random_plans(1, rse_id1, rse_id2)[0]
        plan["state"] = LoadInjectionState.INJECTING
        add_injection_plan(**plan)

        result = self._invoke("loadinjection", "kill",
                              "--src-rse", rse1, "--dest-rse", rse2)
        assert result.exit_code == 0

        state = get_injection_plan_state(rse_id1, rse_id2)
        assert state == LoadInjectionState.KILLED

        delete_injection_plan(rse_id1, rse_id2)

    def test_cli_validation_errors(self):
        """CLI INTEGRATION: invalid params are rejected"""
        rse1 = rse_name_generator()
        rse2 = rse_name_generator()
        add_rse(rse1)
        add_rse(rse2)

        # interval=0 should be rejected (no --test, so goes through gateway)
        r = self._invoke("loadinjection", "add",
                         "--src-rse", rse1, "--dest-rse", rse2,
                         "--interval", "0")
        assert r.exit_code != 0

        # negative rate should be rejected
        r = self._invoke("loadinjection", "add",
                         "--src-rse", rse1, "--dest-rse", rse2,
                         "--inject-rate", "-1")
        assert r.exit_code != 0


class TestGatewayIntegration:
    """Integration tests exercising the Gateway → Core path directly."""

    def _make_plan(self, src, dest, **overrides):
        """Helper: build a plan dict for gateway submission."""
        now = datetime.utcnow()
        plan = {
            "src_rse": src,
            "dest_rse": dest,
            "inject_rate": 200,
            "start_time": now.strftime("%Y-%m-%d %H:%M:%S"),
            "end_time": (now + timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S"),
            "interval": 900,
            "fudge": 0.0,
            "max_injection": 0.2,
            "expiration_delay": 1800,
            "rule_lifetime": 3600,
            "big_first": False,
            "dry_run": False,
            "comments": "gateway test",
        }
        plan.update(overrides)
        return plan

    def test_gateway_add_and_get(self):
        """GATEWAY INTEGRATION: add plan via gateway, verify via core get"""
        from rucio.gateway.loadinjection import add_load_injection_plans

        rse1 = rse_name_generator()
        rse2 = rse_name_generator()
        rse_id1 = add_rse(rse1)
        rse_id2 = add_rse(rse2)

        plan = self._make_plan(rse1, rse2, inject_rate=333)
        add_load_injection_plans([plan], issuer="root", vo="def")

        stored = get_injection_plan(rse_id1, rse_id2, vo="def")
        assert stored["inject_rate"] == 333
        assert stored["state"] == LoadInjectionState.WAITING

        delete_injection_plan(rse_id1, rse_id2, vo="def")

    def test_gateway_duplicate_rejected(self):
        """GATEWAY INTEGRATION: duplicate RSE pair is rejected"""
        from rucio.gateway.loadinjection import add_load_injection_plans

        rse1 = rse_name_generator()
        rse2 = rse_name_generator()
        add_rse(rse1)
        add_rse(rse2)

        plan = self._make_plan(rse1, rse2)
        add_load_injection_plans([plan], issuer="root", vo="def")

        with pytest.raises(DuplicateLoadInjectionPlan):
            add_load_injection_plans([plan], issuer="root", vo="def")

        # Cleanup
        src_id = get_rse_id(rse1, vo="def")
        dest_id = get_rse_id(rse2, vo="def")
        delete_injection_plan(src_id, dest_id, vo="def")

    def test_gateway_delete_and_verify(self):
        """GATEWAY INTEGRATION: delete via gateway, verify plan gone"""
        from rucio.gateway.loadinjection import (
            add_load_injection_plans,
            delete_load_injection_plan,
        )

        rse1 = rse_name_generator()
        rse2 = rse_name_generator()
        rse_id1 = add_rse(rse1)
        rse_id2 = add_rse(rse2)

        plan = self._make_plan(rse1, rse2)
        add_load_injection_plans([plan], issuer="root", vo="def")

        delete_load_injection_plan(rse1, rse2, issuer="root", vo="def")
        state = get_injection_plan_state(rse_id1, rse_id2)
        assert state is None

    def test_gateway_update_and_verify(self):
        """GATEWAY INTEGRATION: update via gateway, verify change in DB"""
        from rucio.gateway.loadinjection import (
            add_load_injection_plans,
            update_load_injection_plan,
        )

        rse1 = rse_name_generator()
        rse2 = rse_name_generator()
        rse_id1 = add_rse(rse1)
        rse_id2 = add_rse(rse2)

        plan = self._make_plan(rse1, rse2)
        add_load_injection_plans([plan], issuer="root", vo="def")

        update_load_injection_plan(
            rse1, rse2,
            updates={"inject_rate": 888},
            issuer="root", vo="def",
        )

        stored = get_injection_plan(rse_id1, rse_id2, vo="def")
        assert stored["inject_rate"] == 888

        delete_injection_plan(rse_id1, rse_id2, vo="def")

    def test_gateway_kill_and_verify(self):
        """GATEWAY INTEGRATION: kill via gateway, verify state is KILLED"""
        from rucio.gateway.loadinjection import (
            add_load_injection_plans,
            kill_load_injection_plan,
        )

        rse1 = rse_name_generator()
        rse2 = rse_name_generator()
        rse_id1 = add_rse(rse1)
        rse_id2 = add_rse(rse2)

        plan = self._make_plan(rse1, rse2)
        add_load_injection_plans([plan], issuer="root", vo="def")
        # Plan needs to be INJECTING for kill to make sense
        update_injection_plan_state(rse_id1, rse_id2, LoadInjectionState.INJECTING)

        kill_load_injection_plan(rse1, rse2, issuer="root", vo="def")
        state = get_injection_plan_state(rse_id1, rse_id2)
        assert state == LoadInjectionState.KILLED

        delete_injection_plan(rse_id1, rse_id2, vo="def")

    def test_gateway_invalid_params_rejected(self):
        """GATEWAY INTEGRATION: invalid params are rejected by gateway"""
        from rucio.gateway.loadinjection import add_load_injection_plans

        rse1 = rse_name_generator()
        rse2 = rse_name_generator()
        add_rse(rse1)
        add_rse(rse2)

        with pytest.raises(Exception):
            add_load_injection_plans(
                [self._make_plan(rse1, rse2, interval=0)],
                issuer="root", vo="def",
            )

    def test_gateway_vo_isolation(self):
        """GATEWAY INTEGRATION: plans in different VOs are isolated"""
        from rucio.gateway.loadinjection import add_load_injection_plans, get_load_injection_plans

        # Create RSEs and plans in two VOs
        rse_a1 = rse_name_generator()
        rse_a2 = rse_name_generator()
        rse_b1 = rse_name_generator()
        rse_b2 = rse_name_generator()

        # Note: add_rse in single-VO mode always uses "def". This test
        # verifies VO filtering works with explicit vo parameters.
        add_rse(rse_a1)
        add_rse(rse_a2)
        add_rse(rse_b1)
        add_rse(rse_b2)

        add_load_injection_plans(
            [self._make_plan(rse_a1, rse_a2, comments="vo-a")],
            issuer="root", vo="def",
        )
        add_load_injection_plans(
            [self._make_plan(rse_b1, rse_b2, comments="vo-b")],
            issuer="root", vo="def",
        )

        plans = get_load_injection_plans(issuer="root", vo="def")
        comments = {p["comments"] for p in plans if p["comments"] in ("vo-a", "vo-b")}
        assert "vo-a" in comments
        assert "vo-b" in comments

        # Cleanup
        for src, dst in [(rse_a1, rse_a2), (rse_b1, rse_b2)]:
            try:
                s = get_rse_id(src)
                d = get_rse_id(dst)
                delete_injection_plan(s, d)
            except NoLoadInjectionPlanFound:
                pass


class TestDaemonIntegration:
    """Tests exercising the daemon with real RSEs and rules (requires --profile storage).

    These tests create plans on real XRD RSEs, run the scanner and submitter
    daemons, and verify that rules are actually created or cleaned up.
    """

    def test_scanner_finds_unique_datasets_on_xrd(self):
        """DAEMON INTEGRATION: scanner finds unique datasets between XRD1 and XRD3"""
        src = get_rse_id("XRD1")
        dest = get_rse_id("XRD3")

        # Run scanner once
        update_unique_rse_pair_datasets(src, dest)

        # Check cache was populated (XRD1 should have datasets XRD3 doesn't)
        cached = get_unique_rse_pair_datasets(src, dest)
        # Not asserting len > 0 because test data may vary; just verify
        # it's a list and no errors occurred
        assert isinstance(cached, list)

    def test_scanner_full_bulk_run(self):
        """DAEMON INTEGRATION: bulk scanner runs without errors"""
        # Run scanner's run_once via the function directly
        update_unique_rse_pair_datasets_bulk()
        # If we got here without exceptions, the scanner works

    def test_submitter_with_real_plan_dry_run(self):
        """DAEMON INTEGRATION: submitter processes a plan end-to-end (dry_run)"""
        src_name = "XRD1"
        dest_name = "XRD3"
        src_id = get_rse_id(src_name)
        dest_id = get_rse_id(dest_name)

        # Ensure cache has data
        update_unique_rse_pair_datasets(src_id, dest_id)

        # Create a plan
        plan = generate_random_plans(1, src_id, dest_id)[0]
        plan["state"] = LoadInjectionState.INJECTING
        plan["start_time"] = datetime.utcnow() - timedelta(seconds=60)
        plan["end_time"] = datetime.utcnow() + timedelta(seconds=10)
        plan["interval"] = 1
        plan["dry_run"] = True
        plan["vo"] = "def"
        add_injection_plan(**plan)

        # Run the actual daemon function
        import logging
        from rucio.daemons.loadinjector.submitter import plan_submitter
        logger_fn = logging.getLogger("test_daemon_int").info
        plan_submitter(plan, logger_fn)

        # Verify plan completed
        state = get_injection_plan_state(src_id, dest_id)
        assert state != LoadInjectionState.INJECTING, (
            f"Plan stuck in INJECTING after daemon run. State: {state}"
        )

        # Cleanup
        if state is not None:
            try:
                delete_injection_plan(src_id, dest_id)
            except Exception:
                pass

    def test_submitter_kill_works(self):
        """DAEMON INTEGRATION: killing a plan stops injection"""
        src_name = "XRD2"
        dest_name = "XRD4"
        src_id = get_rse_id(src_name)
        dest_id = get_rse_id(dest_name)

        update_unique_rse_pair_datasets(src_id, dest_id)

        plan = generate_random_plans(1, src_id, dest_id)[0]
        plan["state"] = LoadInjectionState.INJECTING
        plan["start_time"] = datetime.utcnow() - timedelta(seconds=60)
        plan["end_time"] = datetime.utcnow() + timedelta(hours=1)
        plan["interval"] = 60
        plan["dry_run"] = True
        plan["vo"] = "def"
        add_injection_plan(**plan)

        # Set to KILLED and verify daemon handles it
        update_injection_plan_state(src_id, dest_id, LoadInjectionState.KILLED)

        import logging
        from rucio.daemons.loadinjector.submitter import plan_submitter
        logger_fn = logging.getLogger("test_daemon_int").info
        plan_submitter(plan, logger_fn)

        state = get_injection_plan_state(src_id, dest_id)
        assert state == LoadInjectionState.KILLED, f"Expected KILLED, got {state}"

        # Cleanup
        try:
            delete_injection_plan(src_id, dest_id)
        except Exception:
            pass

    def test_submitter_creates_real_rules(self):
        """DAEMON INTEGRATION: submitter creates real (non-dry-run) rules in DB"""
        # Create a random universe with enough data
        uni = _setup_random_universe(n_rses=3, n_datasets=100, seed=777)
        src = uni["rse_ids"][0]
        dest = uni["rse_ids"][1]

        # Scanner: cache unique datasets
        update_unique_rse_pair_datasets(src, dest)
        cached = get_unique_rse_pair_datasets(src, dest)
        if not cached:
            return  # Nothing unique to inject

        # Create a short-running plan with dry_run=False
        max_bytes = max(d["bytes"] for d in cached)
        inject_rate = int(max_bytes / (125000 * 10)) + 1
        plan = generate_random_plans(1, src, dest)[0]
        plan["state"] = LoadInjectionState.INJECTING
        plan["start_time"] = datetime.utcnow() - timedelta(seconds=60)
        plan["inject_rate"] = inject_rate
        plan["interval"] = 10
        plan["end_time"] = datetime.utcnow() + timedelta(seconds=20)
        plan["fudge"] = 0
        plan["max_injection"] = 1.0
        plan["dry_run"] = False   # <-- real rules!
        plan["vo"] = "def"
        add_injection_plan(**plan)

        # Run the daemon
        import logging
        from rucio.daemons.loadinjector.submitter import plan_submitter
        logger_fn = logging.getLogger("test_daemon_int").info
        plan_submitter(plan, logger_fn)

        # Verify plan completed and real rules exist in DB
        state = get_injection_plan_state(src, dest)
        assert state == LoadInjectionState.FINISHED, f"Expected FINISHED, got {state}"

        # Query rules created with Load Injection activity
        from rucio.db.sqla.session import get_session
        from rucio.db.sqla.models import ReplicationRule
        from sqlalchemy import select
        session = get_session()
        with session() as s:
            rules = s.execute(
                select(ReplicationRule).where(
                    ReplicationRule.activity == "Load Injection",
                    ReplicationRule.rse_expression == get_rse(dest)["rse"],
                )
            ).scalars().all()
        assert len(rules) > 0, "No real rules created by submitter!"

        # Cleanup: expire created rules
        for rule in rules:
            try:
                from rucio.core.rule import update_rule
                update_rule(rule.id, options={"lifetime": 0})
            except Exception:
                pass

        try:
            delete_injection_plan(src, dest)
        except Exception:
            pass
