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
import os
import re
import traceback
from os import environ
from random import choice, choices
from string import ascii_letters, ascii_uppercase, digits
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


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption("--suite", 
                     choices=["client", "remote_dbs", "sqlite", "multi_vo", "votest"], 
                     default="remote_dbs",
                     help="Test suite to run (matches existing SUITE env var)")
    parser.addoption("--activate-rses", action="store_true", 
                     help="Activate default RSEs (XRD1, XRD2, XRD3, SSH1)")
    parser.addoption("--keep-db", action="store_true", 
                     help="Keep database from previous run")


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line('markers', 'dirty: marks test as dirty, i.e. tests are leaving structures behind')
    config.addinivalue_line('markers', 'noparallel(reason, groups): marks test being unable to run in parallel to other tests')

    if config.pluginmanager.hasplugin("xdist"):
        from .ruciopytest import xdist_noparallel_scheduler
        config.pluginmanager.register(xdist_noparallel_scheduler)

    # Initialize database before test collection to avoid import-time database connection failures
    suite = config.getoption("--suite", default=None)
    keep_db = config.getoption("--keep-db", default=False)

    if suite and suite != "client":
        import os
        from alembic import command
        from alembic.config import Config
        from rucio.db.sqla.util import purge_db

        print(f"\n[pytest_configure] Setting up database for suite: {suite}")

        if not keep_db:
            print("[pytest_configure] Resetting database tables")

            # Check if we're using SQLite
            from rucio.db.sqla.session import get_engine
            engine = get_engine()
            is_sqlite = 'sqlite' in str(engine.url).lower()

            # Remove old SQLite databases
            sqlite_paths = ['/tmp/rucio.db']
            if is_sqlite:
                for db_path in sqlite_paths:
                    if os.path.exists(db_path):
                        print(f"[pytest_configure] Removing old SQLite database: {db_path}")
                        os.remove(db_path)
                print("[pytest_configure] SQLite database file deleted, skipping purge_db()")
            else:
                # For PostgreSQL/Oracle, use purge_db to handle schemas
                try:
                    print("[pytest_configure] Purging database (dropping tables and PostgreSQL types)")
                    purge_db()
                    print("[pytest_configure] Database purge completed")
                except Exception as e:
                    # Check if error is because schema doesn't exist (fresh database)
                    error_str = str(e).lower()
                    if 'does not exist' in error_str or 'invalidschemaname' in error_str:
                        print(f"[pytest_configure] Schema doesn't exist (fresh database), skipping purge")
                    else:
                        print(f"[pytest_configure] Database purge failed: {e}")
                        import traceback
                        traceback.print_exc()
                        raise RuntimeError("Failed to purge database") from e

            # Fix SQLite permissions if database exists (after build)
            if is_sqlite:
                for db_path in sqlite_paths:
                    if os.path.exists(db_path):
                        print(f"[pytest_configure] Setting SQLite database permissions: {db_path}")
                        os.chmod(db_path, 0o666)

        # Build the database schema and tables
        try:
            from rucio.db.sqla.util import build_database, create_root_account, create_base_vo

            print("[pytest_configure] Building database schema and tables")
            build_database()
            print("[pytest_configure] Database build completed")

            # Create base VO and root account
            print("[pytest_configure] Creating base VO and root account")
            create_base_vo()
            create_root_account()
            print("[pytest_configure] Base VO and root account created")
        except Exception as e:
            print(f"[pytest_configure] Database build failed: {e}")
            import traceback
            traceback.print_exc()
            raise RuntimeError("Failed to build database") from e

        # Restart Apache httpd so it picks up the new database
        try:
            import subprocess
            subprocess.run(['httpd', '-k', 'graceful'], check=True, capture_output=True)
            print("[pytest_configure] Apache httpd restarted")
            # Give httpd a moment to restart
            import time
            time.sleep(2)
        except subprocess.CalledProcessError as e:
            print(f"[pytest_configure] Warning: Could not restart Apache: {e}")
        except FileNotFoundError:
            print("[pytest_configure] Warning: httpd not found, skipping Apache restart")

        # Bootstrap test data (create root account, etc.) before test collection
        # This is needed because some test modules instantiate clients at module level
        try:
            print("[pytest_configure] Bootstrapping test data (root account, etc.)")
            _run_bootstrap_tests()
            print("[pytest_configure] Test data bootstrap completed\n")
        except Exception as e:
            print(f"[pytest_configure] Bootstrap failed: {e}")
            import traceback
            traceback.print_exc()
            raise RuntimeError("Failed to bootstrap test data") from e


def pytest_make_parametrize_id(
        config: pytest.Config,
        val: dict[str, tuple[str, str, Any]],
        argname: str
) -> Optional[str]:
    if argname == 'file_config_mock':
        cfg = {}
        for section, option, value in val.get('overrides', []):
            cfg.setdefault(section, {})[option] = value
        for section, option in val.get('removes', []):
            cfg.setdefault(section, {})[option] = "[REMOVED]"
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
def account_client(rucio_bootstrap) -> "AccountClient":
    from rucio.client.accountclient import AccountClient

    return AccountClient()


@pytest.fixture(scope='module')
def replica_client(rucio_bootstrap) -> "ReplicaClient":
    from rucio.client.replicaclient import ReplicaClient

    return ReplicaClient()


@pytest.fixture(scope='module')
def rucio_client(rucio_bootstrap) -> "Client":
    from rucio.client import Client
    return Client()


@pytest.fixture(scope='module')
def did_client(rucio_bootstrap) -> "DIDClient":
    from rucio.client.didclient import DIDClient

    return DIDClient()


@pytest.fixture(scope='module')
def rse_client(rucio_bootstrap) -> "RSEClient":
    from rucio.client.rseclient import RSEClient

    return RSEClient()


@pytest.fixture(scope='module')
def scope_client(rucio_bootstrap) -> "ScopeClient":
    from rucio.client.scopeclient import ScopeClient

    return ScopeClient()


@pytest.fixture(scope='module')
def dirac_client(rucio_bootstrap) -> "DiracClient":
    from rucio.client.diracclient import DiracClient

    return DiracClient()


@pytest.fixture
def download_client(rucio_bootstrap) -> "DownloadClient":
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

    from rucio.client import Client
    from rucio.common.types import InternalAccount
    from rucio.core.account import add_account, del_account
    from rucio.db.sqla import models
    from rucio.db.sqla.constants import AccountType
    from rucio.tests.common_server import cleanup_db_deps

    account = InternalAccount(''.join(random.choice(string.ascii_lowercase) for _ in range(10)), vo=vo)

    if os.environ.get('SUITE') == 'client':
        c = Client(vo=vo)
        c.add_account(account=account.external, type_="user", email=f'{account.external}@email.com')
        yield account
        c.delete_account(account=account.external)

    else:
        add_account(account=account, type_=AccountType.USER, email=f'{account.external}@email.com')
        yield account
        cleanup_db_deps(model=models.Account, select_rows_stmt=models.Account.account == account)
        del_account(account)


@pytest.fixture
def random_account_factory(vo: str) -> "Iterator[InternalAccount]":
    import random
    import string

    from rucio.client import Client
    from rucio.common.types import InternalAccount
    from rucio.core.account import add_account, del_account
    from rucio.db.sqla import models
    from rucio.db.sqla.constants import AccountType
    from rucio.tests.common_server import cleanup_db_deps

    made_accounts = []

    def make_account() -> InternalAccount:
        account = InternalAccount(''.join(random.choice(string.ascii_lowercase) for _ in range(10)), vo=vo)
        made_accounts.append(account)
        if os.environ.get('SUITE') == 'client':
            c = Client(vo=vo)
            c.add_account(account=account.external, type_="user", email=f'{account.external}@email.com')
        else:
            add_account(account=account, type_=AccountType.USER, email=f'{account.external}@email.com')
        return account

    yield make_account

    for account in made_accounts:
        if os.environ.get('SUITE') == 'client':
            c = Client(vo=vo)
            c.delete_account(account=account.external)
        else:
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
    try:
        mark_iterable = request.instance.pytestmark
    except AttributeError:
        mark_iterable = None
    if not fixture_param and mark_iterable:
        # Parametrize support is incomplete for legacy unittest test cases
        # Manually retrieve the parameters from the list of marks:
        mark = next(iter(filter(lambda m: m.name == 'parametrize', mark_iterable)), None)
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
    DeclarativeObj = type('DeclarativeObj{}'.format(name), (ModelBase,), {})  # noqa: N806
    # Create a new declarative base and map the previously created object into the base
    mapper_registry = registry()
    InMemoryBase = mapper_registry.generate_base(name='InMemoryBase{}'.format(name))  # noqa: N806
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

    in_memory_message = __create_in_memory_db_table(
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

    with mock.patch('rucio.core.message.Message', new=in_memory_message):
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

    in_memory_config = __create_in_memory_db_table(
        'configs_' + generate_uuid(),
        Column('section', String(128)),
        Column('opt', String(128)),
        Column('value', String(4000)),
        table_args=(PrimaryKeyConstraint('section', 'opt', name='CONFIGS_PK'),),
    )

    # Fill the table with the requested mock data
    session = get_session()()
    for section, option, value in (table_content or []):
        in_memory_config(section=section, opt=option, value=value).save(flush=True, session=session)
    session.commit()

    with mock.patch('rucio.core.config.models.Config', new=in_memory_config):
        yield


@pytest.fixture(scope="session")
def temp_config_file() -> "Iterator[ConfigParser]":
    """
    Session-scoped fixture that generates a temporary file and sets it as the Rucio config file.
    Used to test when no Rucio config file is already present.
    """
    import tempfile

    # Create a temporary file
    with tempfile.NamedTemporaryFile(delete=True) as temp:
        # Set the environment variable to the name of the temporary file
        with pytest.MonkeyPatch.context() as mp:
            mp.setenv("RUCIO_CONFIG", temp.name)
            yield mp


@pytest.fixture
def file_config_mock(request: pytest.FixtureRequest) -> "Iterator[ConfigParser]":
    """
    Fixture which allows to have an isolated in-memory configuration file instance which
    is not persisted after exiting the fixture.

    This override works only in tests which use config calls directly, not in the ones working
    via the API, as the server config is not changed.
    """
    from unittest import mock

    from rucio.common.config import Config, config_add_section, config_has_option, config_has_section, config_remove_option, config_set

    # Get the fixture parameters
    overrides = []
    removes = []
    params = __get_fixture_param(request)
    if params:
        overrides = params.get("overrides", overrides)
        removes = params.get("removes", removes)

    parser = Config().parser
    with mock.patch('rucio.common.config.get_config', side_effect=lambda: parser):
        for section, option, value in (overrides or []):
            if not config_has_section(section):
                config_add_section(section)
            config_set(section, option, value)
        for section, option in (removes or []):
            if config_has_section(section) and config_has_option(section, option):
                config_remove_option(section, option)
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


@pytest.fixture
def rse_protocol() -> "Iterator[dict[str, Any]]":
    yield {
        "hostname": "example.com",
        "scheme": "root",
        "port": 1094,
        "prefix": "//defdatadisk/rucio/",
        "domains": {
            "wan": {
                "read": 1,
            }
        },
    }


@pytest.fixture
def doi_factory() -> "Callable[[], str]":
    """Fixture that returns a function to generate random DOIs."""

    def generate_doi() -> str:
        return '10.1234/' + ''.join(choices(ascii_letters + digits, k=10))  # noqa: S311

    return generate_doi


@pytest.fixture
def db_read_session():
    from rucio.db.sqla.constants import DatabaseOperationType
    from rucio.db.sqla.session import db_session

    """
    Fixture to provide a read-only database session.
    This session is used for read operations and should not modify the database.
    """

    with db_session(DatabaseOperationType.READ) as session:
        yield session


@pytest.fixture
def db_write_session():
    from rucio.db.sqla.constants import DatabaseOperationType
    from rucio.db.sqla.session import db_session

    """
    Fixture to provide a write database session.
    This session is used for write operations and can modify the database.
    """

    with db_session(DatabaseOperationType.WRITE) as session:
        yield session


@pytest.fixture(scope="session", autouse=True)
def test_environment_setup(request: pytest.FixtureRequest) -> None:
    """
    Session-level setup for test environment based on suite type.
    Handles memcached, cleanup, and basic environment preparation.
    """
    import os
    import subprocess
    import tempfile
    from pathlib import Path
    
    suite = request.config.getoption("--suite")
    
    # Set SUITE environment variable for compatibility with existing code
    os.environ['SUITE'] = suite
    
    if suite == "client":
        # Client-only tests need minimal setup
        return
    
    # Server tests need full environment setup
    print("Setting up test environment for suite:", suite)
    
    # Start memcached if not running
    try:
        subprocess.run(['memcached', '-u', 'root', '-d'], check=False, capture_output=True)
    except FileNotFoundError:
        print("Warning: memcached not found, skipping memcached setup")
    
    # Clear memcache
    try:
        with open('/dev/tcp/127.0.0.1/11211', 'w') as f:
            f.write('flush_all\n')
    except:
        # Alternative method using netcat or telnet if direct socket fails
        try:
            subprocess.run(['echo', 'flush_all'], stdout=subprocess.PIPE, check=False)
        except:
            print("Warning: Could not clear memcache")
    
    # Cleanup temporary files
    temp_patterns = [
        '/tmp/.rucio_*/',
        '/tmp/rucio_rse/*'
    ]
    
    for pattern in temp_patterns:
        try:
            import glob
            for path in glob.glob(pattern):
                if os.path.isdir(path):
                    import shutil
                    shutil.rmtree(path, ignore_errors=True)
                elif os.path.isfile(path):
                    os.remove(path)
        except Exception as e:
            print(f"Warning: Could not cleanup {pattern}: {e}")
    
    # Clean .pyc files from lib directory
    try:
        subprocess.run(['find', 'lib', '-iname', '*.pyc', '-delete'], 
                      check=False, capture_output=True)
    except Exception as e:
        print(f"Warning: Could not clean .pyc files: {e}")


@pytest.fixture(scope="session", autouse=True)
def database_setup(request: pytest.FixtureRequest, test_environment_setup) -> None:
    """
    Session-level database setup marker.
    The actual database initialization is done in pytest_configure hook
    to ensure it happens before test collection.
    This fixture now only serves as a dependency marker for other fixtures.
    """
    suite = request.config.getoption("--suite")

    if suite == "client":
        pytest.skip("Client tests don't need database setup")

    # Database is already initialized in pytest_configure
    print("[database_setup] Database already initialized in pytest_configure")


@pytest.fixture(scope="session", autouse=True)
def rucio_bootstrap(request: pytest.FixtureRequest, database_setup, test_environment_setup) -> None:
    """
    Session-level Rucio bootstrap setup.
    Handles Apache restart, test data bootstrap, RSE sync, and metadata sync.
    """
    import os
    import subprocess
    import sys
    import time
    from pathlib import Path
    
    suite = request.config.getoption("--suite")
    activate_rses = request.config.getoption("--activate-rses")
    
    if suite == "client":
        print("Client suite: minimal bootstrap")
        # Set client-specific configuration
        source_path = os.environ.get('RUCIO_HOME', '/opt/rucio')
        client_cfg = f"{source_path}/etc/docker/test/extra/rucio_client.cfg"
        target_cfg = f"{source_path}/etc/rucio.cfg"
        
        if os.path.exists(client_cfg):
            import shutil
            shutil.copy2(client_cfg, target_cfg)
            print(f"Copied client config from {client_cfg} to {target_cfg}")
        return
    
    print("[rucio_bootstrap] Server suite: full bootstrap")

    # httpd restart and bootstrap are already done in pytest_configure
    print("[rucio_bootstrap] httpd and test data already initialized in pytest_configure")
    
    # Sync RSE repository - execute sync logic directly
    try:
        print("Syncing RSE repository")
        if suite == "special" and os.path.exists('etc/rse_repository.json.special'):
            _run_sync_rses(['etc/rse_repository.json.special'])
        else:
            _run_sync_rses([])
        print("RSE repository sync completed")
    except Exception as e:
        print(f"RSE sync failed: {e}")
        import traceback
        traceback.print_exc()
        pytest.fail("Failed to sync RSE repository")
    
    # Sync metadata keys - execute sync logic directly
    try:
        print("Syncing metadata keys")
        _run_sync_meta()
        print("Metadata sync completed")
    except Exception as e:
        print(f"Metadata sync failed: {e}")
        import traceback
        traceback.print_exc()
        pytest.fail("Failed to sync metadata")
    
    # Activate RSEs if requested
    if activate_rses:
        print("Activating default RSEs (XRD1, XRD2, XRD3, SSH1)")
        try:
            result = subprocess.run(['tools/docker_activate_rses.sh'], 
                                  check=True, capture_output=True, text=True)
            print("RSE activation completed")
        except subprocess.CalledProcessError as e:
            print(f"RSE activation failed: {e}")
            print(f"stdout: {e.stdout}")
            print(f"stderr: {e.stderr}")
            pytest.fail("Failed to activate RSEs")
        except FileNotFoundError:
            print("Warning: docker_activate_rses.sh not found, skipping RSE activation")


def _run_bootstrap_tests() -> None:
    """Execute bootstrap_tests.py logic directly."""
    import time
    from json import dumps
    
    import requests
    
    from rucio.client import Client
    from rucio.common.config import config_get, config_get_bool
    from rucio.common.constants import DEFAULT_VO
    from rucio.common.exception import Duplicate, DuplicateContent, RucioException
    from rucio.common.types import InternalAccount
    from rucio.common.utils import extract_scope
    from rucio.core.account import add_account_attribute
    from rucio.core.vo import map_vo
    from rucio.gateway.vo import add_vo
    from rucio.tests.common_server import reset_config_table
    
    # Create config table including the long VO mappings
    reset_config_table()
    if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
        vo = {'vo': map_vo(config_get('client', 'vo', raise_exception=False, default='tst'))}
        try:
            add_vo(new_vo=vo['vo'], issuer='super_root', description='A VO to test multi-vo features', email='N/A', vo=DEFAULT_VO)
        except Duplicate:
            print(f'VO {vo["vo"]} already added')
    else:
        vo = {}

    try:
        client = Client()
    except RucioException as e:
        error_msg = str(e)
        print('Creating client failed:', error_msg)
        if 'Internal Server Error' in error_msg:
            server_log = '/var/log/rucio/httpd_error_log'
            if os.path.exists(server_log):
                # wait for the server to write the error to log
                time.sleep(5)
                with open(server_log, 'r') as fhandle:
                    print(fhandle.readlines()[-200:], file=sys.stderr)
        raise

    try:
        client.add_account('jdoe', 'SERVICE', 'jdoe@email.com')
    except Duplicate:
        print('Account jdoe already added')

    try:
        add_account_attribute(account=InternalAccount('root', **vo), key='admin', value=True)
    except Exception as error:
        print(error)

    try:
        client.add_account('panda', 'SERVICE', 'panda@email.com')
        add_account_attribute(account=InternalAccount('panda', **vo), key='admin', value=True)
    except Duplicate:
        print('Account panda already added')

    try:
        client.add_scope('jdoe', 'mock')
    except Duplicate:
        print('Scope mock already added')

    try:
        client.add_scope('root', 'archive')
    except Duplicate:
        print('Scope archive already added')


def _run_sync_rses(argv: list) -> None:
    """Execute sync_rses.py logic directly."""
    import json
    import traceback
    
    from rucio.client import Client
    from rucio.common.exception import Duplicate, InvalidObject

    if len(argv) == 1:
        rse_repo = argv[0]
    else:
        rse_repo = 'etc/rse_repository.json'

    try:
        with open(rse_repo) as f:
            rses_list = json.load(f)
    except Exception:
        print("Failed to load RSE repository file")
        traceback.print_exc()
        raise

    c = Client()

    for rse in rses_list:
        try:
            c.add_rse(rse)
        except Duplicate:
            pass
        except:
            print("Failed to add RSE " + rse)
            traceback.print_exc()

        try:
            for p_id in rses_list[rse]['protocols']:
                try:
                    c.add_protocol(rse, p_id)
                except Duplicate:
                    pass
                except:
                    print("Failed to add protocol to RSE " + rse + ": " + str(p_id))
                    traceback.print_exc()
        except KeyError:
            pass

        try:
            for attr in rses_list[rse]['attributes']:
                try:
                    c.add_rse_attribute(rse, attr, rses_list[rse]['attributes'][attr])
                except Duplicate:
                    pass
                except:
                    print("Failed to add attribute " + attr + " to RSE " + rse)
                    traceback.print_exc()
        except KeyError:
            pass


def _run_sync_meta() -> None:
    """Execute sync_meta.py logic directly."""
    import traceback
    
    from rucio.client import Client
    from rucio.common.exception import Duplicate

    meta_keys = [('project', 'ALL', None, ['data13_hip', 'NoProjectDefined']),
                 ('run_number', 'ALL', None, ['NoRunNumberDefined']),
                 ('stream_name', 'ALL', None, ['NoStreamNameDefined']),
                 ('prod_step', 'ALL', None, ['merge', 'recon', 'simul', 'evgen', 'NoProdstepDefined', 'user']),
                 ('datatype', 'ALL', None, ['HITS', 'AOD', 'EVNT', 'NTUP_TRIG', 'NTUP_SMWZ', 'NoDatatypeDefined', 'DPD']),
                 ('version', 'ALL', None, []),
                 ('campaign', 'ALL', None, []),
                 ('guid', 'FILE', r'^(\{){0,1}[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}(\}){0,1}$', []),
                 ('events', 'DERIVED', r'^\d+$', [])]

    c = Client()

    for key, key_type, value_regexp, values in meta_keys:
        try:
            c.add_did_meta(key, key_type, value_regexp)
        except Duplicate:
            pass
        except Exception:
            print("Failed to add key " + key)
            traceback.print_exc()

        for value in values:
            try:
                c.add_did_meta(key, key_type, value_regexp, value)
            except Duplicate:
                pass
            except Exception:
                print("Failed to add value " + value + " to key " + key)
                traceback.print_exc()
