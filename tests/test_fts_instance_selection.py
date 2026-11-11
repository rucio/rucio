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

import pytest

from rucio.common.constants import RseAttr
from rucio.core import distance as distance_core
from rucio.core import replica as replica_core
from rucio.core import rse as rse_core
from rucio.core import rule as rule_core
from rucio.core.request import list_and_mark_transfer_requests_and_source_replicas
from rucio.core.topology import Topology
from rucio.core.transfer import ProtocolFactory, build_transfer_paths
from rucio.transfertool.fts3 import FTS3Transfertool

SRC_FTS = "https://fts-src:8446"
MID_FTS = "https://fts-mid:8446"
DST_FTS = "https://fts-dst:8446"
GCS_SIGN_URL = "gcs"
S3_SIGN_URL = "s3"


def _make_transfer_path(did, rse_factory, root_account, *rses_attrs):
    """
    Create a chain of mock RSEs, one per attribute dict, and return the transfer path along it.

    Distances only link neighbours in the chain, so with three or more RSEs the only route is
    a multihop through the intermediate ones.
    """
    # Define the RSEs: the first is the source, the last the destination
    rse_ids = []
    for attrs in rses_attrs:
        rse_name, rse_id = rse_factory.make_mock_rse()
        for key, value in attrs.items():
            rse_core.add_rse_attribute(rse_id, key, value)
        rse_ids.append(rse_id)
    for hop_src_id, hop_dst_id in zip(rse_ids, rse_ids[1:]):
        distance_core.add_distance(hop_src_id, hop_dst_id, distance=1)
    src_rse_id, dst_rse_id, dst_rse = rse_ids[0], rse_ids[-1], rse_name

    # Make sure the source contains a replica of the file
    file = {"scope": did["scope"], "name": did["name"], "bytes": 1}
    replica_core.add_replicas(
        rse_id=src_rse_id,
        files=[file],
        account=root_account,
    )

    # Add rule to copy file to destination RSE
    rule_core.add_rule(
        dids=[did],
        account=root_account,
        copies=1,
        rse_expression=dst_rse,
        grouping="ALL",
        weight=None,
        lifetime=None,
        locked=False,
        subscription_id=None,
    )

    # Create RSE network, allowing the intermediate RSEs to be used as hops
    topology = Topology(rse_ids=rse_ids).configure_multihop(multihop_rse_ids=set(rse_ids[1:-1]))

    # Fetch path between source and destination RSE
    requests_by_id = list_and_mark_transfer_requests_and_source_replicas(
        rse_collection=topology, rses=[src_rse_id, dst_rse_id]
    )
    paths_by_request, *_ = build_transfer_paths(
        topology=topology,
        protocol_factory=ProtocolFactory(),
        requests_with_sources=requests_by_id.values(),
    )
    _, [transfer_path] = next(iter(paths_by_request.items()))
    assert len(transfer_path) == len(rse_ids) - 1
    return transfer_path


def _make_single_hop_path(did, rse_factory, root_account, src_attrs, dst_attrs):
    """Create two mock RSEs with the given attributes and return the transfer path between them."""
    return _make_transfer_path(did, rse_factory, root_account, src_attrs, dst_attrs)


def _selected_host(builder):
    return dict(builder.fixed_kwargs)["external_host"]


def test_single_hop_uses_destination_fts(did_factory, rse_factory, root_account):
    """With FTS on both RSEs, the destination's server is used."""
    did = did_factory.random_file_did()
    transfer_path = _make_single_hop_path(
        did, rse_factory, root_account,
        src_attrs={RseAttr.FTS: SRC_FTS},
        dst_attrs={RseAttr.FTS: DST_FTS},
    )

    sub_path, builder = FTS3Transfertool.submission_builder_for_path(transfer_path)

    assert sub_path == transfer_path
    assert _selected_host(builder) == DST_FTS


@pytest.mark.parametrize("src_attrs, dst_attrs", [
    ({RseAttr.FTS: SRC_FTS}, {}),
    ({}, {RseAttr.FTS: DST_FTS}),
], ids=["no-dst-fts", "no-src-fts"])
def test_single_hop_not_fts_capable_without_fts_on_both_rses(src_attrs, dst_attrs, did_factory, rse_factory, root_account):
    """Without fts on both the source and the destination, the path is not FTS-capable, so ([], None) is returned."""
    did = did_factory.random_file_did()
    transfer_path = _make_single_hop_path(
        did, rse_factory, root_account,
        src_attrs=src_attrs,
        dst_attrs=dst_attrs,
    )

    sub_path, builder = FTS3Transfertool.submission_builder_for_path(transfer_path)

    assert sub_path == []
    assert builder is None


def test_single_hop_uses_source_fts_when_source_is_gcs(did_factory, rse_factory, root_account):
    """With FTS on both RSEs and the source RSE is GCS, the source's server is used."""
    did = did_factory.random_file_did()
    transfer_path = _make_single_hop_path(
        did, rse_factory, root_account,
        src_attrs={RseAttr.FTS: SRC_FTS, RseAttr.SIGN_URL: GCS_SIGN_URL},
        dst_attrs={RseAttr.FTS: DST_FTS},
    )

    sub_path, builder = FTS3Transfertool.submission_builder_for_path(transfer_path)

    assert sub_path == transfer_path
    assert _selected_host(builder) == SRC_FTS


def test_single_hop_non_gcs_sign_url_uses_destination_fts(did_factory, rse_factory, root_account):
    """Only GCS triggers the source exception; other sign_url services still use the destination's server."""
    did = did_factory.random_file_did()
    transfer_path = _make_single_hop_path(
        did, rse_factory, root_account,
        src_attrs={RseAttr.FTS: SRC_FTS, RseAttr.SIGN_URL: S3_SIGN_URL},
        dst_attrs={RseAttr.FTS: DST_FTS},
    )

    sub_path, builder = FTS3Transfertool.submission_builder_for_path(transfer_path)

    assert sub_path == transfer_path
    assert _selected_host(builder) == DST_FTS


def test_single_hop_uses_first_of_comma_separated_fts(did_factory, rse_factory, root_account):
    """A comma-separated fts attribute is split and only the first server is used."""
    did = did_factory.random_file_did()
    transfer_path = _make_single_hop_path(
        did, rse_factory, root_account,
        src_attrs={RseAttr.FTS: SRC_FTS},
        dst_attrs={RseAttr.FTS: f"{DST_FTS},{MID_FTS}"},
    )

    sub_path, builder = FTS3Transfertool.submission_builder_for_path(transfer_path)

    assert sub_path == transfer_path
    assert _selected_host(builder) == DST_FTS


def test_multihop_uses_last_hop_destination_fts(did_factory, rse_factory, root_account):
    """For a multihop path, the server chosen for the last hop (its destination's) is used for the whole path."""
    did = did_factory.random_file_did()
    transfer_path = _make_transfer_path(
        did, rse_factory, root_account,
        {RseAttr.FTS: SRC_FTS},
        {RseAttr.FTS: MID_FTS},
        {RseAttr.FTS: DST_FTS},
    )

    sub_path, builder = FTS3Transfertool.submission_builder_for_path(transfer_path)

    assert sub_path == transfer_path
    assert _selected_host(builder) == DST_FTS


def test_multihop_truncated_when_final_destination_has_no_fts(did_factory, rse_factory, root_account):
    """Hops are taken until one is not FTS-capable; the server of the last capable hop is used."""
    did = did_factory.random_file_did()
    transfer_path = _make_transfer_path(
        did, rse_factory, root_account,
        {RseAttr.FTS: SRC_FTS},
        {RseAttr.FTS: MID_FTS},
        {},
    )

    sub_path, builder = FTS3Transfertool.submission_builder_for_path(transfer_path)

    assert sub_path == transfer_path[:1]
    assert _selected_host(builder) == MID_FTS
