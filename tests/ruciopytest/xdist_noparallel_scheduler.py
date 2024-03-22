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
import itertools
import math

import pytest
from xdist.scheduler import LoadScheduling

from . import NoParallelGroups, xdist_noparallel_remote


@pytest.hookimpl
def pytest_xdist_getremotemodule():
    return xdist_noparallel_remote


@pytest.hookimpl
def pytest_xdist_make_scheduler(config, log):
    return NoParallelScheduler(config=config, log=log)


class DisJointSets:
    """
    Classical Union/find disjoint-set data structure
    """
    def __init__(self, nodes):
        self.parent = {n: n for n in nodes}
        self.rank = {n: 1 for n in nodes}
        self.nb_sets = len(nodes)

    def union(self, u, v):
        root_u, root_v = self.find(u), self.find(v)
        if root_u == root_v:
            return True
        if self.rank[root_u] > self.rank[root_v]:
            self.parent[root_v] = root_u
        elif self.rank[root_v] > self.rank[root_u]:
            self.parent[root_u] = root_v
        else:
            self.parent[root_u] = root_v
            self.rank[root_v] += 1
        self.nb_sets -= 1
        return False

    def find(self, u):
        while u != self.parent[u]:
            self.parent[u] = self.parent[self.parent[u]]
            u = self.parent[u]
        return u


class NoParallelScheduler(LoadScheduling):
    def __init__(self, config, log=None):
        self._noparallel_marks_by_index = None
        self._indexes_by_noparallel_mark = None
        self._blocked_by = None
        super().__init__(config=config, log=log)

    def add_node_collection(self, node, collection):
        if self._noparallel_marks_by_index is None:
            self._noparallel_marks_by_index = {}
            self._indexes_by_noparallel_mark = {}
            for i, data in enumerate(collection.values()):
                noparallel_marks = frozenset(data.get('noparallel', []))
                # all other noparallel markers don't matter if exclusive is set
                if NoParallelGroups.EXCLUSIVE.value in noparallel_marks:
                    noparallel_marks = frozenset((NoParallelGroups.EXCLUSIVE.value,))
                self._noparallel_marks_by_index[i] = noparallel_marks
                for n in noparallel_marks:
                    self._indexes_by_noparallel_mark.setdefault(n, set()).add(i)

        super().add_node_collection(node, list(collection))

    def schedule(self):
        assert self.collection_is_completed

        if self.collection is None:

            if not self._check_nodes_have_same_collection():
                self.log("**Different tests collected, aborting run**")
                return

            # all nodes must have the same collection. Just pick the one of the first node
            self.collection = next(iter(self.node2collection.values()))
            self.pending[:] = range(len(self.collection))

            # For each test, find the tests it blocks from running
            blocked_by = {}
            for test_index, test_marks in self._noparallel_marks_by_index.items():
                blocked_by[test_index] = set()
                if NoParallelGroups.EXCLUSIVE.value in test_marks:
                    # An "exclusive" noparallel test blocks all other tests.
                    blocked_by[test_index].update(self.pending)
                    continue

                # Two tests with the same noparallel mark cannot be run in parallel.
                for m in test_marks:
                    blocked_by[test_index].update(self._indexes_by_noparallel_mark[m])
            self._blocked_by = blocked_by

            # Run in priority the tests which block the most other tests from running
            self.pending.sort(key=lambda x: -len(blocked_by[x]))

        for node in self.nodes:
            self.check_schedule(node)

    def check_schedule(self, node, duration=0):
        if node.shutting_down:
            return

        all_pending = set(itertools.chain(*self.node2pending.values(), self.pending))

        # Use the disjoint-set data structure to find the transitive closure of conflicts.
        # For example testA(mark1), testB(mark1, mark2), and testC(mark2) will be considered
        # in the same conflict set. testA and testC conflict due to transitivity via testB.
        disjoint_sets = DisJointSets(all_pending)
        for test_index in all_pending:
            # We are not interested in tests which already finished
            self._blocked_by[test_index].intersection_update(all_pending)

            for conflict in self._blocked_by[test_index]:
                disjoint_sets.union(test_index, conflict)

            # All tests are in the same disjoint set. So nothing can be run in parallel.
            if disjoint_sets.nb_sets == 1:
                break

        # Must be at least 2 because xdist doesn't execute anything unless there are 2 items in the queue.
        # Send bigger bulks if there are many tests to execute.
        desired_queue_len = max(2.0, math.log2(len(self.pending) or 1))

        for n in self.nodes:
            if len(self.node2pending[n]) > desired_queue_len / 2:
                continue

            self._try_send_to_node(n, disjoint_sets, desired_queue_len)

    def _try_send_to_node(self, node, disjoint_sets, desired_queue_len):

        # We chose to never run in parallel the tests belonging to the same transitive set.
        # Otherwise, deadlocks are possible. Find all transitive sets active on other nodes.
        active_sets_on_other_nodes = set(
            disjoint_sets.find(item_index)
            for item_index in itertools.chain.from_iterable(
                pending for n, pending in self.node2pending.items() if n != node
            )
        )

        to_send = 0
        current = 0
        while current < len(self.pending) and to_send < desired_queue_len - len(self.node2pending[node]):
            test_index = self.pending[current]
            current += 1

            if disjoint_sets.find(test_index) in active_sets_on_other_nodes:
                continue

            self.pending[current - 1], self.pending[to_send] = self.pending[to_send], self.pending[current - 1]
            to_send += 1

        if to_send:
            self._send_tests(node, to_send)
            self.log("num items waiting for node:", len(self.pending))

        if not self.pending:
            node.shutdown()
