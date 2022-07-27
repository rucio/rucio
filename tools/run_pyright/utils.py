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

import json
import threading
from pathlib import Path
from typing import Any, TypeVar, Iterable, Callable, Dict, List


_T = TypeVar('_T')
_K = TypeVar('_K')


def group_by(iterable: Iterable[_T], key: Callable[[_T], _K]) -> Dict[_K, List[_T]]:
    result: Dict[_K, List[_T]] = {}
    for elem in iterable:
        k = key(elem)
        result.setdefault(k, []).append(elem)
    return result


def load_json(path: Path) -> Any:
    with open(path, 'r') as f:
        return json.load(f)


def save_json(path: Path, data: Dict[str, Any]) -> None:
    with open(path, 'w') as file:
        json.dump(data, file, indent=4)
        file.write('\n')


def indent(text: str, prefix: str) -> str:
    """Prepends `prefix` to each line in `text` except the first."""
    return text.replace('\n', '\n' + prefix)


def run_in_background(func: Callable[..., _T], *args, **kwargs) -> Callable[[], _T]:
    return_value: _T

    def run():
        nonlocal return_value
        return_value = func(*args, **kwargs)

    thread = threading.Thread(target=run)
    thread.start()

    def waiter() -> _T:
        thread.join()
        return return_value

    return waiter
