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
import datetime
import itertools
import logging
import threading
import weakref
from collections.abc import Callable, Iterable, Iterator
from decimal import Decimal
from typing import TYPE_CHECKING, cast, Any, Generic, Optional, TypeVar, Union

from sqlalchemy import and_, select

from rucio.common.config import config_get_int, config_get
from rucio.common.exception import NoDistance, RSEProtocolNotSupported, InvalidRSEExpression
from rucio.common.utils import PriorityQueue
from rucio.core.rse import RseCollection, RseData
from rucio.core.rse_expression_parser import parse_expression
from rucio.db.sqla import models
from rucio.db.sqla.session import read_session, transactional_session
from rucio.rse import rsemanager as rsemgr

LoggerFunction = Callable[..., Any]
_Number = Union[int, Decimal]
TN = TypeVar("TN", bound="Node")
TE = TypeVar("TE", bound="Edge")

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from typing import Protocol

    class _StateProvider(Protocol):
        @property
        def cost(self) -> _Number:
            ...

        @property
        def enabled(self) -> bool:
            ...

    TNState = TypeVar("TNState", bound=_StateProvider)
    TEState = TypeVar("TEState", bound=_StateProvider)


DEFAULT_HOP_PENALTY = 10
INF = float('inf')


class Node(RseData):
    def __init__(self, rse_id: str):
        super().__init__(rse_id)

        self.in_edges = weakref.WeakKeyDictionary()
        self.out_edges = weakref.WeakKeyDictionary()

        self.cost: _Number = 0
        self.enabled: bool = True
        self.used_for_multihop = False


class Edge(Generic[TN]):
    def __init__(self, src_node: TN, dst_node: TN):
        self._src_node = weakref.ref(src_node)
        self._dst_node = weakref.ref(dst_node)

        self.cost: _Number = 1
        self.enabled: bool = True

        self.add_to_nodes()

    def add_to_nodes(self):
        self.src_node.out_edges[self.dst_node] = self
        self.dst_node.in_edges[self.src_node] = self

    def remove_from_nodes(self):
        self.src_node.out_edges.pop(self.dst_node, None)
        self.dst_node.in_edges.pop(self.src_node, None)

    @property
    def src_node(self) -> TN:
        node = self._src_node()
        if node is None:
            # This shouldn't happen if the Node list is correctly managed by the Topology object.
            raise ReferenceError("weak reference returned None")
        return node

    @property
    def dst_node(self) -> TN:
        node = self._dst_node()
        if node is None:
            # This shouldn't happen if the Node list is correctly managed by the Topology object.
            raise ReferenceError("weak reference returned None")
        return node

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        return self._src_node == other._src_node and self._dst_node == other._dst_node

    def __str__(self):
        return f'{self._src_node}-->{self._dst_node}'


class Topology(RseCollection, Generic[TN, TE]):
    """
    Helper private class used to easily fetch topological information for a subset of RSEs.
    """
    def __init__(
            self,
            rse_ids: Optional[Iterable[str]] = None,
            ignore_availability: bool = False,
            node_cls: type[TN] = Node,
            edge_cls: type[TE] = Edge,
    ):
        super().__init__(rse_ids=rse_ids, rse_data_cls=node_cls)
        self._edge_cls = edge_cls
        self._edges = {}
        self._edges_loaded = False
        self._multihop_nodes = set()
        self._hop_penalty = DEFAULT_HOP_PENALTY
        self.ignore_availability = ignore_availability

        self._lock = threading.RLock()

    @transactional_session
    def ensure_loaded(
            self,
            rse_ids: "Optional[Iterable[str]]" = None,
            load_name: bool = False,
            load_columns: bool = False,
            load_attributes: bool = False,
            load_info: bool = False,
            load_usage: bool = False,
            load_limits: bool = False,
            include_deleted: bool = False,
            *,
            session: "Session",
    ):

        if not rse_ids:
            with self._lock:
                rse_ids = list(self.rse_id_to_data_map)
        super().ensure_loaded(
            rse_ids=rse_ids,
            load_name=load_name,
            load_columns=load_columns,
            load_attributes=load_attributes,
            load_info=load_info,
            load_usage=load_usage,
            load_limits=load_limits,
            include_deleted=include_deleted,
            session=session,
        )

    def get_or_create(self, rse_id: str) -> "TN":
        rse_data = self.rse_id_to_data_map.get(rse_id)
        if rse_data is None:
            with self._lock:
                rse_data = self.rse_id_to_data_map.get(rse_id)
                if not rse_data:
                    self.rse_id_to_data_map[rse_id] = rse_data = self._rse_data_cls(rse_id)
                    # A new node added. Edges which were already loaded are probably incomplete now.
                    self._edges_loaded = False
        return rse_data

    @property
    def edges(self):
        with self._lock:
            return copy.copy(self._edges)

    def edge(self, src_node: TN, dst_node: TN) -> "Optional[TE]":
        return self._edges.get((src_node, dst_node))

    def get_or_create_edge(self, src_node: TN, dst_node: TN) -> "TE":
        edge = self._edges.get((src_node, dst_node))
        if not edge:
            with self._lock:
                edge = self._edges.get((src_node, dst_node))
                if not edge:
                    self._edges[src_node, dst_node] = edge = self._edge_cls(src_node, dst_node)
        return edge

    def delete_edge(self, src_node: TN, dst_node: TN):
        with self._lock:
            edge = self._edges[src_node, dst_node]
            edge.remove_from_nodes()

    @property
    def multihop_enabled(self) -> bool:
        return True if self._multihop_nodes else False

    @read_session
    def configure_multihop(self, multihop_rse_ids: Optional[set[str]] = None, *, session: "Session", logger: LoggerFunction = logging.log):
        with self._lock:
            return self._configure_multihop(multihop_rse_ids=multihop_rse_ids, session=session, logger=logger)

    def _configure_multihop(self, multihop_rse_ids: Optional[set[str]] = None, *, session: "Session", logger: LoggerFunction = logging.log):

        if multihop_rse_ids is None:
            multihop_rse_expression = config_get('transfers', 'multihop_rse_expression', default='available_for_multihop=true', expiration_time=600, session=session)

            multihop_rse_ids = set()
            if multihop_rse_expression.strip():
                try:
                    multihop_rse_ids = {rse['id'] for rse in parse_expression(multihop_rse_expression, session=session)}
                except InvalidRSEExpression:
                    pass
                if not multihop_rse_ids:
                    logger(logging.WARNING, 'multihop_rse_expression is not empty, but returned no RSEs')

        for node in self._multihop_nodes:
            node.used_for_multihop = False

        self._multihop_nodes.clear()

        for rse_id in multihop_rse_ids:
            node = self.get_or_create(rse_id).ensure_loaded(load_columns=True)
            if self.ignore_availability or (node.columns['availability_read'] and node.columns['availability_write']):
                node.used_for_multihop = True
                self._multihop_nodes.add(node)

        self._hop_penalty = config_get_int('transfers', 'hop_penalty', default=DEFAULT_HOP_PENALTY, session=session)
        return self

    @read_session
    def ensure_edges_loaded(self, *, session: "Session"):
        """
        Ensure that all edges are loaded for the (sub-)set of nodes known by this topology object
        """
        if self._edges_loaded:
            return

        with self._lock:
            return self._ensure_edges_loaded(session=session)

    def _ensure_edges_loaded(self, *, session: "Session"):
        stmt = select(
            models.Distance
        ).where(
            and_(
                models.Distance.src_rse_id.in_(self.rse_id_to_data_map.keys()),
                models.Distance.dest_rse_id.in_(self.rse_id_to_data_map.keys()),
            )
        )

        loaded_edges = set()
        for distance in session.execute(stmt).scalars():
            if distance.distance is None:
                continue

            src_node = self[distance.src_rse_id]
            dst_node = self[distance.dest_rse_id]
            edge = self.get_or_create_edge(src_node, dst_node)

            sanitized_dist = int(distance.distance) if distance.distance >= 0 else 0
            edge.cost = sanitized_dist

            loaded_edges.add((src_node, dst_node))

        if len(loaded_edges) != len(self._edges):
            # Remove edges which don't exist in the database anymore
            to_remove = set(self._edges).difference(loaded_edges)
            for src_node, dst_node in to_remove:
                self.delete_edge(src_node, dst_node)

        self._edges_loaded = True

    @read_session
    def search_shortest_paths(
            self,
            src_nodes: list[TN],
            dst_node: TN,
            operation_src: str,
            operation_dest: str,
            domain: str,
            limit_dest_schemes: list[str],
            *,
            session: "Session",
    ) -> dict[TN, list[dict[str, Any]]]:
        """
        Find the shortest paths from multiple sources towards dest_rse_id.
        """

        for rse in itertools.chain(src_nodes, [dst_node], self._multihop_nodes):
            rse.ensure_loaded(load_attributes=True, load_info=True, session=session)
        self.ensure_edges_loaded(session=session)

        if self._multihop_nodes:
            # Filter out island source RSEs
            nodes_to_find = {node for node in src_nodes if node.out_edges}
        else:
            nodes_to_find = set(src_nodes)

        class _NodeStateProvider:
            _hop_penalty = self._hop_penalty

            def __init__(self, node: TN):
                self.enabled: bool = True
                self.cost: _Number = 0
                if node != dst_node:
                    try:
                        self.cost = int(node.attributes.get('hop_penalty', self._hop_penalty))
                    except ValueError:
                        self.cost = self._hop_penalty

        scheme_missmatch_found = {}

        class _EdgeStateProvider:
            def __init__(self, edge: TE):
                self.edge = edge
                self.chosen_scheme = {}

            @property
            def cost(self) -> _Number:
                return self.edge.cost

            @property
            def enabled(self) -> bool:
                try:
                    matching_scheme = rsemgr.find_matching_scheme(
                        rse_settings_src=self.edge.src_node.info,
                        rse_settings_dest=self.edge.dst_node.info,
                        operation_src=operation_src,
                        operation_dest=operation_dest,
                        domain=domain,
                        scheme=limit_dest_schemes if self.edge.dst_node == dst_node and limit_dest_schemes else None,
                    )
                    self.chosen_scheme = {
                        'source_scheme': matching_scheme[1],
                        'dest_scheme': matching_scheme[0],
                        'source_scheme_priority': matching_scheme[3],
                        'dest_scheme_priority': matching_scheme[2],
                    }
                    return True
                except RSEProtocolNotSupported:
                    scheme_missmatch_found[self.edge.src_node] = True
                    return False

        paths = {dst_node: []}
        for node, distance, _, edge_to_next_hop, edge_state in self.dijkstra_spf(dst_node=dst_node,
                                                                                 nodes_to_find=nodes_to_find,
                                                                                 node_state_provider=_NodeStateProvider,
                                                                                 edge_state_provider=_EdgeStateProvider):
            nh_node = edge_to_next_hop.dst_node
            edge_state = cast(_EdgeStateProvider, edge_state)
            hop = {
                'source_rse': node,
                'dest_rse': nh_node,
                'hop_distance': edge_state.cost,
                'cumulated_distance': distance,
                **edge_state.chosen_scheme,
            }
            paths[node] = [hop] + paths[nh_node]

            nodes_to_find.discard(node)
            if not nodes_to_find:
                # We found the shortest paths to all desired nodes
                break

        result = {}
        for node in src_nodes:
            path = paths.get(node)
            if path is not None:
                result[node] = path
            elif scheme_missmatch_found.get(node):
                result[node] = []
        return result

    def dijkstra_spf(
            self,
            dst_node: TN,
            nodes_to_find: Optional[set[TN]] = None,
            node_state_provider: "Callable[[TN], TNState]" = lambda x: x,
            edge_state_provider: "Callable[[TE], TEState]" = lambda x: x,
    ) -> "Iterator[tuple[TN, _Number, TNState, TE, TEState]]":
        """
        Does a Backwards Dijkstra's algorithm: start from destination and follow inbound links to other nodes.
        If multihop is disabled, stop after analysing direct connections to dest_rse.
        If the optional nodes_to_find parameter is set, will restrict search only towards these nodes.
        Otherwise, traverse the graph in integrality.

        Will yield nodes in order of their distance from the destination.
        """

        priority_q = PriorityQueue()
        priority_q[dst_node] = 0
        next_hops: dict[TN, tuple[_Number, TNState, Optional[TE], Optional[TEState]]] =\
            {dst_node: (0, node_state_provider(dst_node), None, None)}
        while priority_q:
            node = priority_q.pop()
            node_dist, node_state, edge_to_nh, edge_to_nh_state = next_hops[node]

            if edge_to_nh is not None and edge_to_nh_state is not None:  # skip dst_node
                yield node, node_dist, node_state, edge_to_nh, edge_to_nh_state

            if self._multihop_nodes or edge_to_nh is None:
                # If multihop is disabled, only examine neighbors of dst_node

                for adjacent_node, edge in node.in_edges.items():

                    if nodes_to_find is None or adjacent_node in nodes_to_find or adjacent_node.used_for_multihop:

                        edge_state = edge_state_provider(edge)
                        new_adjacent_dist = node_dist + node_state.cost + edge_state.cost
                        if new_adjacent_dist < next_hops.get(adjacent_node, (INF, ))[0] and edge_state.enabled:
                            adj_node_state = node_state_provider(adjacent_node)
                            next_hops[adjacent_node] = new_adjacent_dist, adj_node_state, edge, edge_state
                            priority_q[adjacent_node] = new_adjacent_dist


class ExpiringObjectCache:
    """
    Thread-safe container which builds and object with the function passed in parameter and
    caches it for the TTL duration.
    """

    def __init__(self, ttl, new_obj_fnc):
        self._lock = threading.Lock()
        self._object = None
        self._creation_time = None
        self._new_obj_fnc = new_obj_fnc
        self._ttl = ttl

    def get(self, logger=logging.log):
        with self._lock:
            if not self._object \
                    or not self._creation_time \
                    or datetime.datetime.utcnow() - self._creation_time > datetime.timedelta(seconds=self._ttl):
                self._object = self._new_obj_fnc()
                self._creation_time = datetime.datetime.utcnow()
                logger(logging.INFO, "Refreshed topology object")
            return self._object


@transactional_session
def get_hops(
        source_rse_id: str,
        dest_rse_id: str,
        multihop_rse_ids: Optional[set[str]] = None,
        limit_dest_schemes: Optional[list[str]] = None,
        *, session: "Session",
):
    """
    Get a list of hops needed to transfer date from source_rse_id to dest_rse_id.
    Ideally, the list will only include one item (dest_rse_id) since no hops are needed.
    :param source_rse_id:       Source RSE id of the transfer.
    :param dest_rse_id:         Dest RSE id of the transfer.
    :param multihop_rse_ids:    List of RSE ids that can be used for multihop. If empty, multihop is disabled.
    :param limit_dest_schemes:  List of destination schemes the matching scheme algorithm should be limited to for a single hop.
    :returns:                   List of hops in the format [{'source_rse_id': source_rse_id, 'source_scheme': 'srm', 'source_scheme_priority': N, 'dest_rse_id': dest_rse_id, 'dest_scheme': 'srm', 'dest_scheme_priority': N}]
    :raises:                    NoDistance
    """
    if not limit_dest_schemes:
        limit_dest_schemes = []

    topology = Topology().configure_multihop(multihop_rse_ids=multihop_rse_ids)
    src_node = topology[source_rse_id]
    dst_node = topology[dest_rse_id]
    shortest_paths = topology.search_shortest_paths(src_nodes=[src_node], dst_node=dst_node,
                                                    operation_src='third_party_copy_read', operation_dest='third_party_copy_write',
                                                    domain='wan', limit_dest_schemes=limit_dest_schemes, session=session)

    path = shortest_paths.get(src_node)
    if path is None:
        raise NoDistance()

    if not path:
        raise RSEProtocolNotSupported()

    return path
