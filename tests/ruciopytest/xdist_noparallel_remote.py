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

import os
import sys

import pytest
from xdist.remote import Config, _prepareconfig, remote_initconfig, setup_config
from xdist.remote import WorkerInteractor as OriginalWorkerInteractor  # noqa

from tests.ruciopytest import NoParallelGroups


class WorkerInteractor(OriginalWorkerInteractor):

    @pytest.hookimpl
    def pytest_collection_finish(self, session):
        """
        Overrides the base class function to send additional data to the scheduler node.

        Instead of sending a list of test names, it will now send a dictionary giving, for each test name,
        some additional data used by our custom scheduler.
        """
        try:
            topdir = str(self.config.rootpath)
        except AttributeError:  # pytest <= 6.1.0
            topdir = str(self.config.rootdir)

        try:
            collected_items = self._format_items(session.items)
            self.sendevent("collectionfinish", topdir=topdir, ids=collected_items)
        except Exception as e:
            print(e)
            raise

    @staticmethod
    def _format_items(items):
        collected_items = {}
        for item in items:
            item_data = {}

            # Add the 'noparallel' markers as strings
            for mark in list(item.iter_markers('noparallel')):
                noparallel_data = item_data.setdefault('noparallel', [])
                for g in mark.kwargs.get('groups', [NoParallelGroups.EXCLUSIVE]):
                    if isinstance(g, NoParallelGroups):
                        g = g.value
                    else:
                        g = str(g)
                    noparallel_data.append(g)

            collected_items[item.nodeid] = item_data
        return collected_items


# The code below is copy-pasted unchanged from xdist:
# https://github.com/pytest-dev/pytest-xdist/blob/7e1768f838808d13cc813dc27b28495e3042bbf9/src/xdist/remote.py#L327
# TODO: remove this (if xdist ever learns to pass additional data on top of node IDs)

if __name__ == "__channelexec__":
    channel = channel  # type: ignore[name-defined] # noqa: PLW0127, F821
    workerinput, args, option_dict, change_sys_path = channel.receive()  # type: ignore[name-defined]

    if change_sys_path is None:
        importpath = os.getcwd()
        sys.path.insert(0, importpath)
        os.environ["PYTHONPATH"] = (
            importpath + os.pathsep + os.environ.get("PYTHONPATH", "")
        )
    else:
        sys.path = change_sys_path

    os.environ["PYTEST_XDIST_TESTRUNUID"] = workerinput["testrunuid"]
    os.environ["PYTEST_XDIST_WORKER"] = workerinput["workerid"]
    os.environ["PYTEST_XDIST_WORKER_COUNT"] = str(workerinput["workercount"])

    if hasattr(Config, "InvocationParams"):
        config = _prepareconfig(args, None)
    else:
        config = remote_initconfig(option_dict, args)
        config.args = args

    setup_config(config, option_dict.get("basetemp"))
    config._parser.prog = os.path.basename(workerinput["mainargv"][0])
    config.workerinput = workerinput  # type: ignore[attr-defined]
    config.workeroutput = {}  # type: ignore[attr-defined]
    interactor = WorkerInteractor(config, channel)  # type: ignore[name-defined]
    config.hook.pytest_cmdline_main(config=config)
