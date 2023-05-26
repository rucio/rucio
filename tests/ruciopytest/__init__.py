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

import enum

class NoParallelGroups(enum.Enum):
    # Special group. Tests with this marker will never run in parallel with any other test
    EXCLUSIVE = 'exclusive'
    # Per-daemon-groups. Running the same daemon multiple times in parallel will fail due to job assignment by hash
    PREPARER = 'preparer'
    THROTTLER = 'throttler'
    STAGER = 'stager'
    SUBMITTER = 'submitter'
    POLLER = 'poller'
    RECEIVER = 'receiver'
    FINISHER = 'finisher'
    # Accessing predefined RSEs
    XRD = 'xrd'

