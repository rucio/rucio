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

import itertools
import logging
import weakref
from typing import TYPE_CHECKING, Any, Callable, Generic, Iterable, Dict, List, Optional, Set, Type, TypeVar

from dogpile.cache.api import NoValue
from sqlalchemy import select, false

from rucio.common.utils import PriorityQueue
from rucio.common.cache import make_region_memcached
from rucio.common.config import config_get_int, config_get
from rucio.common.exception import NoDistance, RSEProtocolNotSupported, InvalidRSEExpression
from rucio.core.rse import RseCollection, RseData
from rucio.core.rse_expression_parser import parse_expression
from rucio.db.sqla import models
from rucio.db.sqla.session import read_session, transactional_session
from rucio.rse import rsemanager as rsemgr

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

LoggerFunction = Callable[..., Any]
TN = TypeVar("TN", bound="Node")
TE = TypeVar("TE", bound="Edge")

REGION = make_region_memcached(expiration_time=600)
DEFAULT_HOP_PENALTY = 10


class Node(RseData):
    def __init__(self, rse_id: str):
        super().__init__(rse_id)

        self.in_edges = weakref.WeakKeyDictionary()
        self.out_edges = weakref.WeakKeyDictionary()
        self.in_edges_fully_loaded = False
        self.out_edges_fully_loaded = False

        self.used_for_multihop = False


class Edge:
    def __init__(self, src_node: Node, dst_node: Node):
        self._src_node = weakref.ref(src_node)
        self._dst_node = weakref.ref(dst_node)

        self.cost = 0

        self.add_to_nodes()

    def add_to_nodes(self):
        self.src_node.out_edges[self.dst_node] = self
        self.dst_node.in_edges[self.src_node] = self

    def remove_from_nodes(self):
        self.src_node.out_edges.pop(self.dst_node, None)
        self.dst_node.in_edges.pop(self.src_node, None)

    @property
    def src_node(self) -> Node:
        node = self._src_node()
        if node is None:
            # This shouldn't happen if the Node list is correctly managed by the Topology object.
            raise ReferenceError("weak reference returned None")
        return node

    @property
    def dst_node(self) -> Node:
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
            node_cls: Type[TN] = Node,
            edge_cls: Type[TE] = Edge,
    ):
        super().__init__(rse_ids=rse_ids, rse_data_cls=node_cls)
        self._edge_cls = edge_cls
        self._edges = {}
        self._multihop_nodes = set()
        self._hop_penalty = DEFAULT_HOP_PENALTY
        self.ignore_availability = ignore_availability

    def edge(self, src_node: TN, dst_node: TN) -> "Optional[TE]":
        return self._edges.get((src_node, dst_node))

    def get_or_create_edge(self, src_node: TN, dst_node: TN) -> "TE":
        edge = self._edges.get((src_node, dst_node))
        if not edge:
            self._edges[src_node, dst_node] = edge = self._edge_cls(src_node, dst_node)
        return edge

    def delete_edge(self, src_node: TN, dst_node: TN):
        edge = self._edges[src_node, dst_node]
        edge.remove_from_nodes()

    @property
    def multihop_enabled(self) -> bool:
        return True if self._multihop_nodes else False

    @read_session
    def configure_multihop(self, multihop_rse_ids: Optional[Set[str]] = None, *, session: "Session", logger: LoggerFunction = logging.log):

        if multihop_rse_ids is None:
            include_multihop = config_get('transfers', 'use_multihop', default=False, expiration_time=600, session=session)
            multihop_rse_expression = config_get('transfers', 'multihop_rse_expression', default='available_for_multihop=true', expiration_time=600, session=session)

            multihop_rse_ids = set()
            if include_multihop:
                try:
                    multihop_rse_ids = {rse['id'] for rse in parse_expression(multihop_rse_expression, session=session)}
                except InvalidRSEExpression:
                    pass
                if multihop_rse_expression and multihop_rse_expression.strip() and not multihop_rse_ids:
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
    def search_shortest_paths(
            self,
            src_nodes: List[TN],
            dst_node: TN,
            operation_src: str,
            operation_dest: str,
            domain: str,
            limit_dest_schemes: List[str],
            *,
            session: "Session",
    ) -> Dict[TN, List[Dict[str, Any]]]:
        """
        Find the shortest paths from multiple sources towards dest_rse_id.
        Does a Backwards Dijkstra's algorithm: start from destination and follow inbound links towards the sources.
        If multihop is disabled, stop after analysing direct connections to dest_rse. Otherwise, stops when all
        sources where found or the graph was traversed in integrality.
        """

        for rse in itertools.chain(src_nodes, [dst_node], self._multihop_nodes):
            rse.ensure_loaded(load_attributes=True, load_info=True, session=session)

        # Filter out island source RSEs
        self._load_outgoing_edges(src_nodes, session=session)
        nodes_to_find = {node for node in src_nodes if node.out_edges}

        next_hop: Dict[Node, Dict[str, Any]] = {dst_node: {'cumulated_distance': 0}}
        priority_q = PriorityQueue()

        priority_q[dst_node] = 0
        while priority_q:
            current_node = priority_q.pop()

            nodes_to_find.discard(current_node)
            if not nodes_to_find:
                # We found the shortest paths to all desired sources
                break

            current_distance = next_hop[current_node]['cumulated_distance']
            if not current_node.in_edges_fully_loaded:
                self._load_inbound_edges([current_node], session=session)
            for adjacent_node, edge in current_node.in_edges.items():

                if adjacent_node not in nodes_to_find and not adjacent_node.used_for_multihop:
                    continue

                hop_penalty = 0
                if current_node != dst_node:
                    try:
                        hop_penalty = int(current_node.attributes.get('hop_penalty', self._hop_penalty))
                    except ValueError:
                        hop_penalty = self._hop_penalty
                new_adjacent_distance = current_distance + edge.cost + hop_penalty
                if next_hop.get(adjacent_node, {}).get('cumulated_distance', 9999) <= new_adjacent_distance:
                    continue

                try:
                    matching_scheme = rsemgr.find_matching_scheme(
                        rse_settings_src=adjacent_node.info,
                        rse_settings_dest=current_node.info,
                        operation_src=operation_src,
                        operation_dest=operation_dest,
                        domain=domain,
                        scheme=limit_dest_schemes if adjacent_node == dst_node and limit_dest_schemes else None
                    )
                    next_hop[adjacent_node] = {
                        'source_rse': adjacent_node,
                        'dest_rse': current_node,
                        'source_scheme': matching_scheme[1],
                        'dest_scheme': matching_scheme[0],
                        'source_scheme_priority': matching_scheme[3],
                        'dest_scheme_priority': matching_scheme[2],
                        'hop_distance': edge.cost,
                        'cumulated_distance': new_adjacent_distance,
                    }
                    priority_q[adjacent_node] = new_adjacent_distance
                except RSEProtocolNotSupported:
                    if next_hop.get(adjacent_node) is None:
                        next_hop[adjacent_node] = {}

            if not self._multihop_nodes:
                # Stop after the first iteration, which finds direct connections to destination
                break

        paths = {}
        for node in src_nodes:
            hop = next_hop.get(node)
            if hop is None:
                continue

            path = []
            while hop.get('dest_rse'):
                path.append(hop)
                hop = next_hop[hop['dest_rse']]
            paths[node] = path
        return paths

    @read_session
    def _load_outgoing_edges(self, nodes: Iterable[Node], *, session: "Session"):
        """
        Loads the outgoing edges of the distance graph for given RSEs
        """

        distances = {}
        cache_misses = []
        for node in nodes:
            cached_value = REGION.get('outgoing_edges_%s' % str(node.id))
            if isinstance(cached_value, NoValue):
                cache_misses.append(node.id)
                distances[node.id] = {}
            else:
                distances[node.id] = cached_value

        if cache_misses:
            stmt = select(
                models.Distance
            ).join(
                models.RSE,
                models.RSE.id == models.Distance.dest_rse_id
            ).where(
                models.Distance.src_rse_id.in_(cache_misses),
                models.RSE.deleted == false()
            )
            for distance in session.execute(stmt).scalars():
                if distance.distance is None:
                    continue
                sanitized_dist = distance.distance if distance.distance >= 0 else 0
                distances[distance.src_rse_id][distance.dest_rse_id] = sanitized_dist

        for rse_id in cache_misses:
            REGION.set('outgoing_edges_%s' % str(rse_id), distances[rse_id])

        for src_rse_id, out_distances in distances.items():
            src_node = self.get_or_create(src_rse_id)

            for dst_rse_id, distance in out_distances.items():
                dst_node = self.get_or_create(dst_rse_id)

                edge = self.get_or_create_edge(src_node, dst_node)
                edge.cost = distance

            if len(out_distances) != len(src_node.out_edges):
                # Remove edges which don't exist in the database anymore
                to_remove = {node for node in src_node.out_edges if node.id not in out_distances}
                for dst_node in to_remove:
                    self.delete_edge(src_node, dst_node)

            src_node.out_edges_fully_loaded = True

    @read_session
    def _load_inbound_edges(self, nodes: Iterable[Node], *, session: "Session"):
        """
        Loads the inbound edges of the distance graph for the given RSEs
        """
        distances = {}
        cache_misses = []
        for node in nodes:
            cached_value = REGION.get('inbound_edges_%s' % str(node.id))
            if isinstance(cached_value, NoValue):
                cache_misses.append(node.id)
                distances[node.id] = {}
            else:
                distances[node.id] = cached_value

        if cache_misses:
            stmt = select(
                models.Distance
            ).join(
                models.RSE,
                models.RSE.id == models.Distance.src_rse_id
            ).where(
                models.Distance.dest_rse_id.in_(cache_misses),
                models.RSE.deleted == false()
            )
            for distance in session.execute(stmt).scalars():
                if distance.distance is None:
                    continue
                sanitized_dist = distance.distance if distance.distance >= 0 else 0
                distances[distance.dest_rse_id][distance.src_rse_id] = sanitized_dist

        for rse_id in cache_misses:
            REGION.set('inbound_edges_%s' % str(rse_id), distances[rse_id])

        for dst_rse_id, in_distances in distances.items():
            dst_node = self.get_or_create(dst_rse_id)

            for src_rse_id, distance in in_distances.items():
                src_node = self.get_or_create(src_rse_id)
                edge = self.get_or_create_edge(src_node, dst_node)
                edge.cost = distance

            if len(in_distances) != len(dst_node.in_edges):
                # Remove edges which don't exist in the database anymore
                to_remove = {node for node in dst_node.in_edges if node.id not in in_distances}
                for src_node in to_remove:
                    self.delete_edge(src_node, dst_node)

            dst_node.in_edges_fully_loaded = True


@transactional_session
def get_hops(
        source_rse_id: str,
        dest_rse_id: str,
        multihop_rse_ids: Optional[Set[str]] = None,
        limit_dest_schemes: Optional[List[str]] = None,
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
