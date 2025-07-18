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

import contextlib
import itertools
import json
import os
import tempfile
from collections import namedtuple
from functools import wraps
from os import rename
from random import choice, choices
from string import ascii_letters, ascii_uppercase, digits
from typing import IO, TYPE_CHECKING, Any, Literal, Optional

import pytest
import requests

from rucio.common.config import config_get, config_get_bool, get_config_dirs
from rucio.common.constants import DEFAULT_VO
from rucio.common.utils import execute
from rucio.common.utils import generate_uuid as uuid

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator
    from types import ModuleType

    from werkzeug.test import TestResponse

skip_rse_tests_with_accounts = pytest.mark.skipif(not any(os.path.exists(os.path.join(d, 'rse-accounts.cfg')) for d in get_config_dirs()),
                                                  reason='fails if no rse-accounts.cfg found')
skiplimitedsql = pytest.mark.skipif('RDBMS' in os.environ and os.environ['RDBMS'] == 'sqlite',
                                    reason="does not work in SQLite because of missing features")
skip_multivo = pytest.mark.skipif('SUITE' in os.environ and os.environ['SUITE'] == 'multi_vo',
                                  reason="does not work for multiVO")
skip_non_belleii = pytest.mark.skipif(not ('POLICY' in os.environ and os.environ['POLICY'] == 'belleii'),
                                      reason="specific belleii tests")
skip_outside_gh_actions = pytest.mark.skipif(os.getenv("GITHUB_ACTIONS") != "true",
                                             reason="Skipping tests outside GitHub Actions")


def is_influxdb_available(
        url: str = "http://influxdb:8086",
        timeout: float = 2.0
) -> bool:
    """
    Return True when InfluxDB is up and ready for queries, otherwise False.

    Strategy:
    1. Try /health           → 200 + JSON["status"] == "pass"
    2. Fallback to /ping     → 204
    """
    print(f"Checking InfluxDB availability at {url}")
    try:
        r = requests.get(f"{url}/health", timeout=timeout)
        print(f"InfluxDB /health responded with {r.status_code} and body: {r.text}", r.status_code, r.text)
        if r.status_code == 200 and r.json().get("status") == "pass":
            return True
        print(f"InfluxDB is not running healthy at {url}.")
        return False
    except requests.RequestException as e:
        # /health failed or is not available (pre‑1.8)
        print(f"Failed to query InfluxDB /health at {url}: {e}")

    try:
        print(f"Falling back to /ping for InfluxDB at {url}")
        r = requests.get(f"{url}/ping", timeout=timeout)
        print(f"InfluxDB /ping responded with {r.status_code}")
        return r.status_code == 204
    except requests.RequestException as e:
        print(f"InfluxDB is not reachable at {url}: {e}")
        return False


def is_elasticsearch_available(
        url: str = "http://elasticsearch:9200",
        timeout: float = 2.0,
        min_status: str = 'green',
) -> bool:
    """
    Return True when the Elasticsearch node is reachable **and**
    cluster health is at least `min_status` ('red'<'yellow'<'green').

    1. GET /_cluster/health  → 200 + JSON["status"] meets threshold
    2. Fallback: HEAD /      → 200 (port open but health unknown)
    """
    _status_level = {"red": 1, "yellow": 2, "green": 3}

    print(f"Checking Elasticsearch availability at {url}")
    try:
        r = requests.get(f"{url}/_cluster/health", timeout=timeout)
        print(f"Elasticsearch /_cluster/health responded with {r.status_code} and body: {r.text}")
        if r.status_code == 200:
            status = r.json().get("status")
            if status and _status_level[status] >= _status_level[min_status]:
                return True
            print(f"Elasticsearch health is {status!r}, below threshold {min_status!r}.")
            return False
    except requests.RequestException as e:
        # Either not reachable or /_cluster/health not yet available
        print(f"Failed to query Elasticsearch /_cluster/health at {url}: {e}")

    # Very old nodes or boot‑strapping clusters: fall back to a simple HEAD /
    try:
        print(f"Falling back to HEAD request for Elasticsearch at {url}")
        r = requests.head(url, timeout=timeout)
        print(f"Elasticsearch HEAD / responded with {r.status_code}")
        return r.status_code == 200
    except requests.RequestException as e:
        print(f"Elasticsearch is not reachable at {url}: {e}")
        return False


skip_missing_elasticsearch_influxdb_in_env = pytest.mark.skipif(not (is_influxdb_available() and is_elasticsearch_available()), reason='influxdb is not available')


def get_long_vo() -> str:
    """ Get the VO name from the config file for testing.
    Don't map the name to a short version.
    :returns: VO name string.
    """
    vo_name = DEFAULT_VO
    if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
        vo = config_get('client', 'vo', raise_exception=False, default=None)
        if vo is not None:
            vo_name = vo
    return vo_name


def account_name_generator() -> str:
    """ Generate random account name.

    :returns: A random account name
    """
    return 'jdoe-' + str(uuid()).lower()[:16]


def scope_name_generator() -> str:
    """ Generate random scope name.

    :returns: A random scope name
    """
    return 'mock_' + str(uuid()).lower()[:16]


def did_name_generator(did_type: str = 'file', name_prefix: str = '', name_suffix: str = '', path: Optional[str] = None) -> str:
    """ Generate random DID name.
    :param did_type: A string to create a meaningful did_name depending on the did_type (file, dataset, container)
    :param name_prefix: String to prefix to the DID name
    :param name_suffix: String to append to the DID name
    :param path: If specified, use the path to generate the did_name

    :returns: A random DID name
    """
    if os.getenv('POLICY') == 'belleii':
        if path is not None:
            return path

        container_path = os.path.join("/belle", name_prefix if name_prefix else "mock", 'cont_%s' % str(uuid()))
        if did_type == 'container':
            return container_path

        dataset_path = os.path.join(container_path, 'dataset_%s' % str(uuid()))
        if did_type == 'dataset':
            return dataset_path

        file_path = os.path.join(dataset_path, 'file_%s%s' % (str(uuid()), name_suffix))
        return file_path

    if path is not None:
        return os.path.basename(path)

    return '%s%s_%s%s' % (name_prefix, did_type, str(uuid()), name_suffix)


def rse_name_generator(size: int = 10) -> str:
    """ Generate random RSE name.

    :returns: A random RSE name
    """
    return 'MOCK-' + ''.join(choice(ascii_uppercase) for x in range(size))  # noqa: S311


def rfc2253_dn_generator() -> str:
    """ Generate a random DN in RFC 2253 format.

    :returns: A random DN
    """
    random_cn = ''.join(choices(ascii_letters + digits, k=8))  # noqa: S311
    random_o = ''.join(choices(ascii_letters + digits, k=8))  # noqa: S311
    random_c = ''.join(choices(ascii_letters, k=2))  # noqa: S311
    random_dn = "CN={}, O={}, C={}".format(random_cn, random_o, random_c)
    return random_dn


def file_generator(size: int = 2, namelen: int = 10) -> str:
    """ Create a bogus file and returns it's name.
    :param size: size in bytes
    :returns: The name of the generated file.
    """
    fn = '/tmp/file_' + ''.join(choice(ascii_uppercase) for x in range(namelen))  # noqa: S311
    execute('dd if=/dev/urandom of={0} count={1} bs=1'.format(fn, size))
    return fn


def make_temp_file(dir_: str, data: str) -> str:
    """
    Creates a temporal file and write `data` on it.
    :param data: String to be written on the created file.
    :returns: Name of the temporal file.
    """
    fd, path = tempfile.mkstemp(dir=dir_)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(data)
    return path


@contextlib.contextmanager
def mock_open(module: "ModuleType", file_like_object: IO):
    call_info = {}

    def mocked_open(
            filename: str,
            mode: str = 'r'
    ) -> contextlib.closing[IO]:
        call_info['filename'] = filename
        call_info['mode'] = mode
        file_like_object.close = lambda: None
        return contextlib.closing(file_like_object)

    setattr(module, 'open', mocked_open)
    try:
        yield call_info
    finally:
        file_like_object.seek(0)
        delattr(module, 'open')


def print_response(rest_response: "TestResponse") -> None:
    print('Status:', rest_response.status)
    print()
    nohdrs = True
    for hdr, val in rest_response.headers.items():
        if nohdrs:
            print('Headers:')
            print('-------')
            nohdrs = False
        print('%s: %s' % (hdr, val))

    if not nohdrs:
        print()

    text = rest_response.get_data(as_text=True)
    print(text if text else '<no content>')


def headers(*iterables: "Iterable") -> list[itertools.chain]:
    return list(itertools.chain(*iterables))


def loginhdr(account: str, username: str, password: str) -> "Iterator[tuple[Literal['X-Rucio-Account', 'X-Rucio-Username', 'X-Rucio-Password'], str]]":
    yield 'X-Rucio-Account', str(account)
    yield 'X-Rucio-Username', str(username)
    yield 'X-Rucio-Password', str(password)


def auth(token) -> "Iterator[tuple[Literal['X-Rucio-Auth-Token'], str]]":
    yield 'X-Rucio-Auth-Token', str(token)


def vohdr(vo: str) -> "Iterator[tuple[Literal['X-Rucio-VO'], str]]":
    if vo:
        yield 'X-Rucio-VO', str(vo)


def hdrdict(dictionary: dict[str, Any]) -> "Iterator[tuple[str, str]]":
    for key in dictionary:
        yield str(key), str(dictionary[key])


def accept(mimetype: "Mime") -> "Iterator[tuple[Literal['Accept'], Mime]]":
    yield 'Accept', mimetype


class Mime:
    """ Enum-type class for mimetypes. """
    METALINK = 'application/metalink4+xml'
    JSON = 'application/json'
    JSON_STREAM = 'application/x-json-stream'
    BINARY = 'application/octet-stream'


def load_test_conf_file(file_name: str) -> dict[str, Any]:
    config_dir = next(filter(lambda d: os.path.exists(os.path.join(d, file_name)), get_config_dirs()))
    with open(os.path.join(config_dir, file_name)) as f:
        return json.load(f)


def remove_config(func: "Callable") -> "Callable":
    @wraps(func)
    def wrapper(*args, **kwargs) -> None:
        for configfile in get_config_dirs():
            # Rename the config to <config>.tmp
            try:
                rename(f"{configfile}rucio.cfg", f"{configfile}rucio.cfg.tmp")
            except FileNotFoundError:
                pass  # When a test uses a os.env assigned conf, there's nothing stating the default location has something
        try:
            # Execute the test
            func(*args, **kwargs)
        finally:
            # And put the config back
            for configfile in get_config_dirs():
                try:
                    rename(f"{configfile}rucio.cfg.tmp", f"{configfile}rucio.cfg")
                except FileNotFoundError:
                    pass

    return wrapper


RSE_namedtuple = namedtuple('RSE_namedtuple', ['name', 'id'])
