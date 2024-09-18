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

import json
from typing import TYPE_CHECKING, Any, TypeVar

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable
    from pathlib import Path


_T = TypeVar('_T')
_K = TypeVar('_K')


def group_by(iterable: 'Iterable[_T]', key: 'Callable[[_T], _K]') -> dict[_K, list[_T]]:
    result: dict[_K, list[_T]] = {}
    for elem in iterable:
        k = key(elem)
        result.setdefault(k, []).append(elem)
    return result


def load_json(path: 'Path') -> dict[str, Any]:
    with open(path, 'r') as f:
        return json.load(f)


def save_json(path: 'Path', data: dict[str, Any]) -> None:
    with open(path, 'w') as file:
        json.dump(data, file, indent=4)
        file.write('\n')
