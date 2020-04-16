#!/usr/bin/env python3

# Copyright 2020 CERN for the benefit of the ATLAS collaboration.
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
#
# Authors:
# - Dimitrios Christidis <dimitrios.christidis@cern.ch>, 2020


def merge(*args):
    r"""Merge and compare iterables.

    Each of the ``args`` must be an iterable object.  Their elements
    must be sorted, not have duplicates, be of the same type and
    implement rich comparison methods.  Typically, this function is
    expected to be called with three iterables whose elements are
    ``str``s.

    Returns a ``tuple`` whose first element is the merged element from
    the iterables.  The second element is itself a ``tuple`` of
    ``bools``s, each signifying whether the merged element was found in
    the corresponding iterable.

    Conceptually, the algorithm might look similar to a merge sort
    without divide-and-conquer.  A key distinction is that, when
    merged, each element appears only once.

    Visually, assuming the following state:

                      C---E---F
                     /
                A---B---C---E---F
                     \
                      D---F---G

    When the generator resumes, it will transition to:

                      E---F
                     /
            A---B---C---E---F
                     \
                      D---F---G

    And yield:

            ('C', (True, True, False))
    """
    iterators = [iter(s) for s in args]
    items = [next(s) for s in iterators]

    while any(v is not None for v in items):
        v_min = min(v for v in items if v is not None)
        found = tuple(v == v_min for v in items)
        yield (v_min, found)

        for i in range(len(args)):
            if items[i] == v_min:
                items[i] = next(iterators[i], None)
