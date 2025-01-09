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

import functools
import re
import traceback
from os import environ
from random import choice
from string import ascii_uppercase
from typing import TYPE_CHECKING, Any, Optional

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator
    from configparser import ConfigParser

    from dogpile.cache.region import CacheRegion
    from flask.testing import FlaskClient
    from prometheus_client import CollectorRegistry
    from sqlalchemy.orm.scoping import scoped_session
    from werkzeug.test import TestResponse

    from rucio.client import Client
    from rucio.client.accountclient import AccountClient
    from rucio.client.didclient import DIDClient
    from rucio.client.diracclient import DiracClient
    from rucio.client.downloadclient import DownloadClient
    from rucio.client.replicaclient import ReplicaClient
    from rucio.client.rseclient import RSEClient
    from rucio.client.scopeclient import ScopeClient
    from rucio.common.types import InternalAccount, InternalScope

    from .temp_factories import TemporaryDidFactory, TemporaryFileFactory, TemporaryRSEFactory


_del_test_prefix = functools.partial(re.compile(r'^[Tt][Ee][Ss][Tt]_?').sub, '')
# local imports in the fixtures to make this file loadable in e.g. client tests

pytest_plugins = ('tests.ruciopytest.artifacts_plugin', )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line('markers', 'dirty: marks test as dirty, i.e. tests are leaving structures behind')
    config.addinivalue_line('markers', 'noparallel(reason, groups): marks test being unable to run in parallel to other tests')

    if config.pluginmanager.hasplugin("xdist"):
        from .ruciopytest import xdist_noparallel_scheduler
        config.pluginmanager.register(xdist_noparallel_scheduler)


def pytest_make_parametrize_id(
        config: pytest.Config,
        val: dict[str, tuple[str, str, Any]],
        argname: str
) -> Optional[str]:
    if argname == 'file_config_mock':
        cfg = {}
        for section, option, value in val['overrides']:
            cfg.setdefault(section, {})[option] = value
        return argname + str(cfg)
    if argname == 'core_config_mock':
        cfg = {}
        for section, option, value in val['table_content']:
            cfg.setdefault(section, {})[option] = value
        return argname + str(cfg)
    # return None to let pytest handle the formatting
    return None


@pytest.fixture(scope='session')
def session_scope_prefix() -> str:
    """
    Generate a name prefix to be shared by objects created during this pytest session
    """
    return ''.join(choice(ascii_uppercase) for _ in range(6)) + '-'


@pytest.fixture(scope='module')
def module_scope_prefix(
    request: pytest.FixtureRequest,
    session_scope_prefix: str
) -> str:
    """
    Generate a name prefix to be shared by objects created during this pytest module
    Relies on pytest's builtin fixture "request"
    https://docs.pytest.org/en/6.2.x/reference.html#std-fixture-request
    """
    return session_scope_prefix + _del_test_prefix(request.module.__name__.split('.')[-1]) + '-'


@pytest.fixture(scope='class')
def class_scope_prefix(
    request: pytest.FixtureRequest,
    module_scope_prefix: str
) -> str:
    if not request.cls:
        return module_scope_prefix
    return module_scope_prefix + _del_test_prefix(request.cls.__name__) + '-'


@pytest.fixture(scope='function')
def function_scope_prefix(
    request: pytest.FixtureRequest,
    class_scope_prefix: str
) -> str:
    return class_scope_prefix + _del_test_prefix(request.node.originalname) + '-'


@pytest.fixture(scope='session')
def vo() -> str:
    if environ.get('SUITE', 'remote_dbs') != 'client':
        # Server test, we can use short VO via DB for internal tests
        from rucio.tests.common_server import get_vo
        return get_vo()
    else:
        # Client-only test, only use config with no DB config
        from rucio.tests.common import get_long_vo
        return get_long_vo()


@pytest.fixture(scope='session')
def second_vo() -> str:
    from rucio.common.config import config_get_bool
    from rucio.core.vo import add_vo, vo_exists
    multi_vo = config_get_bool('common', 'multi_vo', raise_exception=False, default=False)
    if not multi_vo:
        pytest.skip('multi_vo mode is not enabled. Running multi_vo tests in single_vo mode would result in failures.')

    new_vo = 'new'
    if not vo_exists(vo=new_vo):
        add_vo(vo=new_vo, description='Test', email='rucio@email.com')
    return new_vo


@pytest.fixture(scope='session')
def long_vo() -> str:
    from rucio.tests.common import get_long_vo
    return get_long_vo()


@pytest.fixture(scope='module')
def account_client() -> "AccountClient":
    from rucio.client.accountclient import AccountClient

    return AccountClient()


@pytest.fixture(scope='module')
def replica_client() -> "ReplicaClient":
    from rucio.client.replicaclient import ReplicaClient

    return ReplicaClient()


@pytest.fixture(scope='module')
def rucio_client() -> "Client":
    from rucio.client import Client
    return Client()


@pytest.fixture(scope='module')
def did_client() -> "DIDClient":
    from rucio.client.didclient import DIDClient

    return DIDClient()


@pytest.fixture(scope='module')
def rse_client() -> "RSEClient":
    from rucio.client.rseclient import RSEClient

    return RSEClient()


@pytest.fixture(scope='module')
def scope_client() -> "ScopeClient":
    from rucio.client.scopeclient import ScopeClient

    return ScopeClient()


@pytest.fixture(scope='module')
def dirac_client() -> "DiracClient":
    from rucio.client.diracclient import DiracClient

    return DiracClient()


@pytest.fixture
def download_client() -> "DownloadClient":
    from rucio.client.downloadclient import DownloadClient

    return DownloadClient()


@pytest.fixture
def rest_client() -> "Iterator[FlaskClient]":
    from flask.testing import FlaskClient

    from rucio.tests.common import print_response
    from rucio.web.rest.flaskapi.v1.main import application

    class WrappedFlaskClient(FlaskClient):
        def __init__(self, *args, **kwargs):
            super(WrappedFlaskClient, self).__init__(*args, **kwargs)

        def open(
                self,
                path: str = '/',
                *args,
                **kwargs
        ) -> "TestResponse":
            print(kwargs.get('method', 'GET'), path)
            response = super(WrappedFlaskClient, self).open(path, *args, **kwargs)
            try:
                print_response(response)
            except Exception:
                traceback.print_exc()
            return response

    _testing = application.testing
    application.testing = True
    application.test_client_class = WrappedFlaskClient
    with application.test_client() as client:
        yield client
    application.test_client_class = None
    application.testing = _testing


@pytest.fixture
def auth_token(
    rest_client: "FlaskClient",
    long_vo: str
) -> str:
    from rucio.tests.common import headers, loginhdr, vohdr

    auth_response = rest_client.get('/auth/userpass', headers=headers(loginhdr('root', 'ddmlab', 'secret'), vohdr(long_vo)))
    assert auth_response.status_code == 200
    token = auth_response.headers.get('X-Rucio-Auth-Token')
    assert token
    return str(token)


@pytest.fixture(scope='module')
def mock_scope(vo: str) -> "InternalScope":
    from rucio.common.types import InternalScope

    return InternalScope('mock', vo=vo)


@pytest.fixture(scope='module')
def test_scope(vo: str) -> "InternalScope":
    from rucio.common.types import InternalScope

    return InternalScope('test', vo=vo)


@pytest.fixture(scope='module')
def root_account(vo: str) -> "InternalAccount":
    from rucio.common.types import InternalAccount

    return InternalAccount('root', vo=vo)


@pytest.fixture(scope='module')
def jdoe_account(vo: str) -> "InternalAccount":
    from rucio.common.types import InternalAccount

    return InternalAccount('jdoe', vo=vo)


@pytest.fixture
def random_account(vo: str) -> "Iterator[InternalAccount]":
    import random
    import string

    from rucio.common.types import InternalAccount
    from rucio.core.account import add_account, del_account
    from rucio.db.sqla import models
    from rucio.db.sqla.constants import AccountType
    from rucio.tests.common_server import cleanup_db_deps

    account = InternalAccount(''.join(random.choice(string.ascii_uppercase) for _ in range(10)), vo=vo)
    add_account(account=account, type_=AccountType.USER, email=f'{account.external}@email.com')
    yield account
    cleanup_db_deps(model=models.Account, select_rows_stmt=models.Account.account == account)
    del_account(account)


@pytest.fixture(scope="module")
def containerized_rses(rucio_client: "Client") -> list[tuple[str, str]]:
    """
    Detects if containerized rses for xrootd & ssh are available in the testing environment.
    :return: A list of (rse_name, rse_id) tuples.
    """
    from rucio.common.exception import InvalidRSEExpression

    rses = []
    try:
        xrd_rses = [x['rse'] for x in rucio_client.list_rses(rse_expression='test_container_xrd=True')]
        xrd_rses = [rucio_client.get_rse(rse) for rse in xrd_rses]
        xrd_containerized_rses = [(rse_obj['rse'], rse_obj['id']) for rse_obj in xrd_rses if "xrd" in rse_obj['rse'].lower()]
        xrd_containerized_rses.sort()
        rses.extend(xrd_containerized_rses)
        ssh_rses = [x['rse'] for x in rucio_client.list_rses(rse_expression='test_container_ssh=True')]
        ssh_rses = [rucio_client.get_rse(rse) for rse in ssh_rses]
        ssh_containerized_rses = [(rse_obj['rse'], rse_obj['id']) for rse_obj in ssh_rses if "ssh" in rse_obj['rse'].lower()]
        ssh_containerized_rses.sort()
        rses.extend(ssh_containerized_rses)
    except InvalidRSEExpression as invalid_rse_expression:
        print("{ex}. Note that containerized RSEs will not be available in non-containerized test environments"
              .format(ex=invalid_rse_expression))
        traceback.print_exc()
    return rses


@pytest.fixture
def rse_factory(
    request: pytest.FixtureRequest,
    vo: str,
    function_scope_prefix: str
) -> "Iterator[TemporaryRSEFactory]":
    from .temp_factories import TemporaryRSEFactory

    session = None
    if 'db_session' in request.fixturenames:
        session = request.getfixturevalue('db_session')

    with TemporaryRSEFactory(vo=vo, name_prefix=function_scope_prefix, db_session=session) as factory:
        yield factory


@pytest.fixture(scope="class")
def rse_factory_unittest(
    request: pytest.FixtureRequest,
    vo: str,
    class_scope_prefix: str
) -> "Iterator[TemporaryRSEFactory]":
    """
    unittest classes can get access to rse_factory fixture via this fixture
    """
    from .temp_factories import TemporaryRSEFactory

    with TemporaryRSEFactory(vo=vo, name_prefix=class_scope_prefix) as factory:
        request.cls.rse_factory = factory  # type: ignore
        yield factory


@pytest.fixture
def did_factory(
    request: pytest.FixtureRequest,
    vo: str,
    mock_scope: "InternalScope",
    function_scope_prefix: str,
    file_factory: "TemporaryFileFactory",
    root_account: "InternalAccount"
) -> "Iterator[TemporaryDidFactory]":
    from .temp_factories import TemporaryDidFactory

    session = None
    if 'db_session' in request.fixturenames:
        session = request.getfixturevalue('db_session')

    with TemporaryDidFactory(vo=vo, default_scope=mock_scope, name_prefix=function_scope_prefix, file_factory=file_factory,
                             default_account=root_account, db_session=session) as factory:
        yield factory


@pytest.fixture
def file_factory(tmp_path_factory: pytest.TempPathFactory) -> "Iterator[TemporaryFileFactory]":
    from .temp_factories import TemporaryFileFactory

    with TemporaryFileFactory(pytest_path_factory=tmp_path_factory) as factory:
        yield factory


@pytest.fixture
def scope_factory() -> "Callable[[Iterable[str], Optional[str]], tuple[str, list[InternalScope]]]":
    from rucio.common.types import InternalAccount, InternalScope
    from rucio.common.utils import generate_uuid
    from rucio.core.scope import add_scope

    def create_scopes(
            vos: "Iterable[str]",
            account_name: Optional[str] = None
    ) -> tuple[str, list["InternalScope"]]:
        scope_uuid = str(generate_uuid()).lower()[:16]
        scope_name = 'shr_%s' % scope_uuid
        created_scopes = []
        for vo in vos:
            scope = InternalScope(scope_name, vo=vo)
            add_scope(scope, InternalAccount(account_name if account_name else 'root', vo=vo))
            created_scopes.append(scope)
        return scope_name, created_scopes

    return create_scopes


class _TagFactory:
    def __init__(self, prefix: str):
        self.prefix = prefix
        self.index = 0

    def new_tag(self) -> str:
        self.index += 1
        return f'{self.prefix}-{self.index}'


@pytest.fixture
def tag_factory(function_scope_prefix: str) -> _TagFactory:
    return _TagFactory(prefix=f'{function_scope_prefix}{"".join(choice(ascii_uppercase) for _ in range(6))}'.replace('_', '-'))


@pytest.fixture(scope='class')
def tag_factory_class(class_scope_prefix: str) -> _TagFactory:
    return _TagFactory(prefix=f'{class_scope_prefix}{"".join(choice(ascii_uppercase) for _ in range(6))}'.replace('_', '-'))


@pytest.fixture
def db_session() -> "Iterator[scoped_session]":
    from rucio.db.sqla import session

    db_session = session.get_session()
    yield db_session
    db_session.commit()
    db_session.close()


def __get_fixture_param(request: pytest.FixtureRequest) -> Any:
    fixture_param = getattr(request, "param", None)
    if not fixture_param and request.instance:
        # Parametrize support is incomplete for legacy unittest test cases
        # Manually retrieve the parameters from the list of marks:
        mark = next(iter(filter(lambda m: m.name == 'parametrize', request.instance.pytestmark)), None)
        if mark:
            fixture_param = mark.args[1][0]
    return fixture_param


def __create_in_memory_db_table(
        name: str,
        *columns,
        **kwargs
):
    """
    Create an in-memory temporary table using the sqlite memory driver.
    Make sqlalchemy aware of that table by registering it via a
    declarative base.
    """
    import datetime

    from sqlalchemy import CheckConstraint, Column, DateTime
    from sqlalchemy.orm import registry
    from sqlalchemy.pool import StaticPool
    from sqlalchemy.schema import Table

    from rucio.db.sqla.models import ModelBase
    from rucio.db.sqla.session import create_engine, get_maker

    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)

    # Create a class which inherits from ModelBase. This will allow us to use the rucio-specific methods like .save()
    DeclarativeObj = type('DeclarativeObj{}'.format(name), (ModelBase,), {})
    # Create a new declarative base and map the previously created object into the base
    mapper_registry = registry()
    InMemoryBase = mapper_registry.generate_base(name='InMemoryBase{}'.format(name))
    table_args = tuple(columns) + tuple(kwargs.get('table_args', ())) + (
        Column("created_at", DateTime, default=datetime.datetime.utcnow),
        Column("updated_at", DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow),
        CheckConstraint('CREATED_AT IS NOT NULL', name=name.upper() + '_CREATED_NN'),
        CheckConstraint('UPDATED_AT IS NOT NULL', name=name.upper() + '_UPDATED_NN'),
    )
    table = Table(
        name,
        InMemoryBase.metadata,
        *table_args
    )
    mapper_registry.map_imperatively(DeclarativeObj, table)
    # Performa actual creation of the in-memory table
    InMemoryBase.metadata.create_all(engine)

    # Register the new table with the associated engine into the sqlalchemy sessionmaker
    # In theory, this code must be protected by rucio.db.scla.session._LOCK, but this code will be executed
    # during test case initialization, so there is no risk here to have concurrent calls from within the
    # same process
    senssionmaker = get_maker()
    senssionmaker.kw.setdefault('binds', {}).update({DeclarativeObj: engine})
    return DeclarativeObj


@pytest.fixture
def message_mock() -> "Iterator[None]":
    """
    Fixture which overrides the Message table with a private instance
    """
    from unittest import mock

    from sqlalchemy import Column

    from rucio.common.utils import generate_uuid
    from rucio.db.sqla.models import GUID, CheckConstraint, Index, PrimaryKeyConstraint, String, Text

    InMemoryMessage = __create_in_memory_db_table(
        'message_' + generate_uuid(),
        Column('id', GUID(), default=generate_uuid),
        Column('event_type', String(256)),
        Column('payload', String(4000)),
        Column('payload_nolimit', Text),
        Column('services', String(256)),
        table_args=(PrimaryKeyConstraint('id', name='MESSAGES_ID_PK'),
                    CheckConstraint('EVENT_TYPE IS NOT NULL', name='MESSAGES_EVENT_TYPE_NN'),
                    CheckConstraint('PAYLOAD IS NOT NULL', name='MESSAGES_PAYLOAD_NN'),
                    Index('MESSAGES_SERVICES_IDX', 'services', 'event_type'))
    )

    with mock.patch('rucio.core.message.Message', new=InMemoryMessage):
        yield


@pytest.fixture
def core_config_mock(request: pytest.FixtureRequest) -> "Iterator[None]":
    """
    Fixture to allow having per-test core.config tables without affecting the other parallel tests.

    This override works only in tests which use core function calls directly, not in the ones working
    via the API, because the normal config table is not touched and the rucio instance answering API
    calls is not aware of this mock.

    This fixture acts by creating a new copy of the "config" sql table using the :memory: sqlite engine.
    Accesses to the "models.Config" table are then redirected to this temporary table via mock.patch().
    """
    from unittest import mock

    from sqlalchemy import Column

    from rucio.common.utils import generate_uuid
    from rucio.db.sqla.models import PrimaryKeyConstraint, String
    from rucio.db.sqla.session import get_session

    # Get the fixture parameters
    table_content = []
    params = __get_fixture_param(request)
    if params:
        table_content = params.get("table_content", table_content)

    InMemoryConfig = __create_in_memory_db_table(
        'configs_' + generate_uuid(),
        Column('section', String(128)),
        Column('opt', String(128)),
        Column('value', String(4000)),
        table_args=(PrimaryKeyConstraint('section', 'opt', name='CONFIGS_PK'),),
    )

    # Fill the table with the requested mock data
    session = get_session()()
    for section, option, value in (table_content or []):
        InMemoryConfig(section=section, opt=option, value=value).save(flush=True, session=session)
    session.commit()

    with mock.patch('rucio.core.config.models.Config', new=InMemoryConfig):
        yield


@pytest.fixture
def file_config_mock(request: pytest.FixtureRequest) -> "Iterator[ConfigParser]":
    """
    Fixture which allows to have an isolated in-memory configuration file instance which
    is not persisted after exiting the fixture.

    This override works only in tests which use config calls directly, not in the ones working
    via the API, as the server config is not changed.
    """
    from unittest import mock

    from rucio.common.config import Config, config_add_section, config_has_section, config_set

    # Get the fixture parameters
    overrides = []
    params = __get_fixture_param(request)
    if params:
        overrides = params.get("overrides", overrides)

    parser = Config().parser
    with mock.patch('rucio.common.config.get_config', side_effect=lambda: parser):
        for section, option, value in (overrides or []):
            if not config_has_section(section):
                config_add_section(section)
            config_set(section, option, value)
        yield parser


@pytest.fixture
def caches_mock(request: pytest.FixtureRequest) -> "Iterator[list[CacheRegion]]":
    """
    Fixture which overrides the different internal caches with in-memory ones for the duration
    of a particular test.

    This override works only in tests which use core function calls directly, not in the ones
    working via API.

    The fixture acts by by mock.patch the REGION object in the provided list of modules to mock.
    """

    from contextlib import ExitStack
    from unittest import mock

    from dogpile.cache import make_region

    caches_to_mock = []
    expiration_time = 600

    params = __get_fixture_param(request)
    if params:
        caches_to_mock = params.get("caches_to_mock", caches_to_mock)
        expiration_time = params.get("expiration_time", expiration_time)

    with ExitStack() as stack:
        mocked_caches = []
        for module in caches_to_mock:
            region = make_region().configure('dogpile.cache.memory', expiration_time=expiration_time)
            stack.enter_context(mock.patch(module, new=region))
            mocked_caches.append(region)

        yield mocked_caches


@pytest.fixture
def metrics_mock() -> "Iterator[CollectorRegistry]":
    """
    Overrides the prometheus metric registry and allows to verify if the desired
    prometheus metrics were correctly recorded.
    """

    from unittest import mock

    from prometheus_client import CollectorRegistry, values

    with mock.patch('rucio.core.monitor.REGISTRY', new=CollectorRegistry()) as registry, \
            mock.patch('rucio.core.monitor.COUNTERS', new={}), \
            mock.patch('rucio.core.monitor.GAUGES', new={}), \
            mock.patch('rucio.core.monitor.TIMINGS', new={}), \
            mock.patch('prometheus_client.values.ValueClass', new=values.MutexValue):
        yield registry


@pytest.fixture(scope='class')
def scope_and_rse(mock_scope, test_scope):
    from rucio.common.utils import execute

    """
    Check if xrd containers rses for xrootd are available in the testing environment.
    :return: A tuple (scope, rse) for the rucio client where scope is mock/test and rse is a string.
    """
    cmd = "rucio rse list --rses 'test_container_xrd=True'"
    print(cmd)
    exitcode, out, err = execute(cmd)
    print(out, err)
    rses = out.split()
    if len(rses) == 0:
        return mock_scope, 'MOCK-POSIX'
    return test_scope, rses[0]
