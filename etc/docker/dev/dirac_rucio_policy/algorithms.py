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
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = [
    "extract_scope_dirac",
    "lfn2pfn_dirac",
]


def extract_scope_dirac(did: str, scopes: Optional["Sequence[str]"]) -> "Sequence[str]":
    """Scope extraction algorithm for DIRAC.

    Assumes LFNs of the form ``/<VO Name>/<scope>/<path>``.
    """
    msg = f"DID {did!r} does not match expected schema: /<VO Name>/<scope>/<path>."
    if not did.startswith("/"):
        raise ValueError(msg)

    components = [comp for comp in did.split("/") if comp != ""]

    # if no "scope" is in the did, e.g. it's just the vo or another path
    # we return the special "root" scope. Needed as the DIRAC integration
    # needs a container to exist with DID /<VO> and that should belong to
    # the scope "root" owned by the admin user.
    if len(components) < 2:
        return "root", did

    return components[1], did


def lfn2pfn_dirac(scope, name, rse, rse_attrs, protocol_attrs):
    return name
