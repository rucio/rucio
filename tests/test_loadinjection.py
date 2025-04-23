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
from sqlalchemy.sql.expression import and_, update

from rucio.client.loadinjectionclient import LoadInjectionClient
from rucio.common.exception import (
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
    update_injection_plan_state,
    validate_unique_rse_pair_dataset,
)
from rucio.core.rse import add_rse, get_rse
from rucio.core.rule import add_rule
from rucio.core.scope import add_scope
from rucio.db.sqla.constants import LoadInjectionState, LockState
from rucio.db.sqla.session import transactional_session, Session
from rucio.db.sqla.models import DatasetLock, DIDType, AccountType
from rucio.tests.common import (
    account_name_generator,
    did_name_generator,
    rse_name_generator,
    scope_name_generator,
)


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


def generate_random_datasets(
    ndatasets: int = 1,
    nrses: int = 1,
) -> tuple[list, list]:
    # Create now account
    account_name = account_name_generator()
    account = InternalAccount(account_name)
    add_account(
        account,
        AccountType.USER,
        account_name + "@test.com",
    )

    # Create new scope
    scope = InternalScope(scope_name_generator())
    add_scope(scope, account)

    # Create new rses and set account limits
    rse_ids = list()
    for _ in range(nrses):
        rse_id = add_rse(rse_name_generator())
        set_local_account_limit(account, rse_id, 1000000000000000000)
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
    add_dids(datasets, account)

    # Create rules for datasets
    rule_ids = list()
    for dataset in datasets:
        rule = {
            "dids": [dataset],
            "account": dataset["account"],
            "copies": 1,
            "rse_expression": get_rse(dataset["rse_id"])["rse"],
            "grouping": "DATASET",
            "weight": None,
            "lifetime": None,
            "locked": True,
            "subscription_id": None,
        }
        rule_id = add_rule(**rule)[0]
        rule_ids.append(rule_id)

    # Update dataset with rule_id
    for dataset in datasets:
        dataset["rule_id"] = rule_ids[datasets.index(dataset)]
    update_dataset_lock_meta(datasets)
    return datasets, rse_ids


def generate_random_extra_rules(datasets: list, rse_ids: list[str]) -> dict:
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
                "rse_expression": get_rse(rse_id)["rse"],
                "grouping": "DATASET",
                "weight": None,
                "lifetime": None,
                "locked": True,
                "subscription_id": None,
            }
            rule_id = add_rule(**rule)[0]
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
    update_dataset_lock_meta(datasets)
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
        raw_plan = copy.deepcopy(new_plan)
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
        for src_rse_id in rse_id:
            for dest_rse_id in rse_id:
                if src_rse_id == dest_rse_id:
                    continue
                plan = generate_random_plans(
                    nplan=1, src_rse_id=src_rse_id, dest_rse_id=dest_rse_id
                )[0]
                plan.pop("plan_id", None)
                plan.pop("state", None)
                raw_plan = copy.deepcopy(plan)
                plan["src_rse"] = rse_name[rse_ids.index(src_rse_id)]
                plan["dest_rse"] = rse_names[rse_ids.index(dest_rse_id)]
                plan.pop("src_rse_id", None)
                plan.pop("dest_rse_id", None)
                raw_plans.append(raw_plan)
                plans.append(plan)
        result = rucio_client.add_load_injection_plans(plans=plans)
        assert result

        # for src_rse_id in rse_ids:
        #     for dest_rse_id in rse_ids:
        #         if src_rse_id == dest_rse_id:
        #             continue
        #         result = get_injection_plan(src_rse_id, dest_rse_id)
        #         for key, value in raw_plans.items():
        #             assert result[key] == value


class TestDaemon:
    pass
