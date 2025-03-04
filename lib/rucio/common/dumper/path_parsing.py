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

import logging

logger = logging.getLogger('rucio_dumps')


def remove_prefix(prefix: list[str], path: list[str]) -> list[str]:
    """
    Remove the specified prefix from the given path.

    :param prefix: The prefix to be removed from the path.
    :param path: The path from which the prefix should be removed.

    :return: The path with the prefix removed.
            If the prefix is not found at the start of the path, the original path is returned.
            If the path is a subset of the prefix, an empty list is returned.
    """

    iprefix = iter(prefix)
    ipath = iter(path)
    try:
        cprefix = next(iprefix)
        cpath = next(ipath)
    except StopIteration:
        # Either the path or the prefix is empty
        return path
    while cprefix != cpath:
        try:
            cprefix = next(iprefix)
        except StopIteration:
            # No parts of the prefix are part of the path
            return path

    while cprefix == cpath:
        cprefix = next(iprefix, None)
        try:
            cpath = next(ipath)
        except StopIteration:
            # The path is a subset of the prefix
            return []

    if cprefix is not None:
        # If the prefix is not depleted maybe it is only a coincidence
        # in one of the components of the paths: return the path as is.
        return path

    rest = list(ipath)
    rest.insert(0, cpath)
    return rest


def components(path: str) -> list[str]:
    """
    Extracts and returns the non-empty components of a given path.

    :param path: input path string to be parsed.

    :return: list of non-empty components of the path.
    """

    components = path.strip().strip('/').split('/')
    return [component for component in components if component != '']
