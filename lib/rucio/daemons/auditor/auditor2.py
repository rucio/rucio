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


class Result:
    """Tags used for the results of the consistency check."""
    DARK = 'DARK'
    LOST = 'LOST'


def consistency(rucio_dump_before, storage_dump, rucio_dump_after, output):
    """Perform a consistency check.

    All parameters should be ``str``s with the paths to the appropriate
    files.

    The storage and Rucio dumps must be sorted and not contain any
    duplicate entries.  Each line must contain solely the local path of
    a file (i.e. by stripping the common base from the absolute path on
    the RSE).

    The results are written to the file located at ``output`` in CSV
    format.  The first field is a tag and the second is the path.

    The table that follows shows all possible outcomes of the
    comparison.  Only the ones marked with (*) are written to the
    output file.  'B' and 'A' are the Rucio dumps generated before and
    after the storage dump 'S'.

            +---------------+------------+
            |  Set          |  Result    |
            +===============+============+
            |  B - (A | S)  |  Deleted   |
            +---------------+------------+
            |  (B & S) - A  |  Deleted   |
            +---------------+------------+
            |  (B & A) - S  |  LOST (*)  |
            +---------------+------------+
            |  B & A & S    |  OK        |
            +---------------+------------+
            |  (B | A) - S  |  DARK (*)  |
            +---------------+------------+
            |  A - (B | S)  |  New       |
            +---------------+------------+
            |  (A & S) - B  |  New       |
            +---------------+------------+
    """
    with open(rucio_dump_before) as fh_rucio_before,\
            open(storage_dump) as fh_storage,\
            open(rucio_dump_after) as fh_rucio_after,\
            open(output, 'w') as fh_output:

        for item in merge((line.rstrip() for line in fh_rucio_before),
                          (line.rstrip() for line in fh_storage),
                          (line.rstrip() for line in fh_rucio_after)):

            path, found = item
            if not found[0] and found[1] and not found[2]:
                print(Result.DARK, path, sep=',', file=fh_output)
            if found[0] and not found[1] and found[2]:
                print(Result.LOST, path, sep=',', file=fh_output)


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
