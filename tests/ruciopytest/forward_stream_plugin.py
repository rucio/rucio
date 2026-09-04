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

"""Container-side helper plugin: forward this pytest run's reports to the host.

Loaded explicitly via ``-p tests.ruciopytest.forward_stream_plugin`` by
:meth:`InfraManager.run_multi_vo`'s per-VO child. That child runs WITHOUT
``--suite`` -- so the main rucio plugin (``tests.ruciopytest.plugin``) is dormant
and never registers the report-stream emitter itself -- yet it IS the faithful,
gating multi_vo execution (xdist + the noparallel scheduler). When
``RUCIO_FORWARD_STREAM`` is set, register the emitter so each report is streamed
to the host-visible JSONL file and replayed into the host's terminal + junit.

Under xdist the controller re-fires worker reports through
``pytest_runtest_logreport``; registering ONLY on the controller (workers carry
``workerinput``) makes every test surface exactly once -- never doubled.
"""


def pytest_configure(config) -> None:
    """Register the host report-stream emitter on the controller (not workers)."""
    if hasattr(config, "workerinput"):
        return  # xdist worker: the controller re-emits our reports to the host
    from . import forwarding

    forwarding.register_container_stream(config)
