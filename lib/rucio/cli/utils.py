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

import errno
import json
import logging
import os
import pydoc
import re
import shutil
import signal
import subprocess  # noqa: S404 -- subprocess used for external commands
import sys
import traceback
from configparser import NoOptionError, NoSectionError
from datetime import datetime
from functools import wraps
from typing import TYPE_CHECKING, Any, Optional, Union

import click
from rich import box
from rich.console import Console, JustifyMethod, RenderableType
from rich.logging import RichHandler
from rich.table import Table
from rich.text import Text

from rucio.client.client import Client
from rucio.common.config import config_get
from rucio.common.exception import (
    AccessDenied,
    CannotAuthenticate,
    DataIdentifierAlreadyExists,
    DataIdentifierNotFound,
    Duplicate,
    DuplicateContent,
    InputValidationError,
    InvalidRSEExpression,
    MissingDependency,
    RSENotFound,
    RucioException,
    RuleNotFound,
    ScopeNotFound,
    UnsupportedOperation,
)
from rucio.common.utils import extract_scope, setup_logger

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from rich.style import StyleType

SUCCESS = 0
FAILURE = 1


def exception_handler(function):
    verbosity = ("-v" in sys.argv) or ("--verbose" in sys.argv)
    logger = setup_logger(module_name=__name__, logger_name="user", verbose=verbosity)

    @wraps(function)
    def new_funct(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except click.exceptions.Exit as error:
            # Exit is evoked every time click ends a program without running anything
            # This error is raised when the help menu is called
            logger.debug("Exited click context")
            if ("-h" not in sys.argv) or ("--help" not in sys.argv):
                return error.exit_code
            return SUCCESS
        except click.MissingParameter as error:
            error.show()
            msg = f"{error}. Please check the command help (-h/--help)."
            logger.error(msg)
            return 2  # Always return an error 2 for an incorrect specification
        except (InputValidationError, click.exceptions.UsageError) as error:
            logger.error(error)
            logger.debug("This means that one you provided an invalid combination of parameters, or incorrect types. Please check the command help (-h/--help).")
            return FAILURE
        except NotImplementedError as error:
            logger.error(f"Cannot run that operation/command combination {error}")
            return FAILURE
        except DataIdentifierNotFound as error:
            logger.error(error)
            logger.debug("This means that the Data IDentifier you provided is not known by Rucio.")
            return error.error_code
        except AccessDenied as error:
            logger.error(error)
            logger.debug("This error is a permission issue. You cannot run this command with your account.")
            return error.error_code
        except DataIdentifierAlreadyExists as error:
            logger.error(error)
            logger.debug("This means that the Data IDentifier you try to add is already registered in Rucio.")
            return error.error_code
        except RSENotFound as error:
            logger.error(error)
            logger.debug("This means that the Rucio Storage Element you provided is not known by Rucio.")
            return error.error_code
        except InvalidRSEExpression as error:
            logger.error(error)
            logger.debug("This means the RSE expression you provided is not syntactically correct.")
            return error.error_code
        except DuplicateContent as error:
            logger.error(error)
            logger.debug("This means that the DID you want to attach is already in the target DID.")
            return error.error_code
        except Duplicate as error:
            logger.error(error)
            logger.debug("This means that you are trying to add something that already exists.")
            return error.error_code
        except TypeError as error:
            logger.error(error)
            logger.debug("This means the parameter you passed has a wrong type.")
            return FAILURE
        except RuleNotFound as error:
            logger.error(error)
            logger.debug("This means the rule you specified does not exist.")
            return error.error_code
        except UnsupportedOperation as error:
            logger.error(error)
            logger.debug("This means you cannot change the status of the DID.")
            return error.error_code
        except MissingDependency as error:
            logger.error(error)
            logger.debug("This means one dependency is missing.")
            return error.error_code
        except KeyError as error:
            if "x-rucio-auth-token" in str(error):
                used_account = None
                try:  # get the configured account from the configuration file
                    used_account = "%s (from rucio.cfg)" % config_get("client", "account")
                except Exception:
                    pass
                try:  # are we overriden by the environment?
                    used_account = "%s (from RUCIO_ACCOUNT)" % os.environ["RUCIO_ACCOUNT"]
                except Exception:
                    pass
                logger.error("Specified account %s does not have an associated identity." % used_account)

            else:
                logger.debug(traceback.format_exc())
                contact = config_get("policy", "support", raise_exception=False)
                support = ("Please follow up with all relevant information at: " + contact) if contact else ""
                logger.error("\nThe object is missing this property: %s\n" 'This should never happen. Please rerun the last command with the "-v" option to gather more information.\n' "%s" % (str(error), support))
            return FAILURE
        except RucioException as error:
            logger.error(error)
            return error.error_code
        except Exception as error:
            if isinstance(error, IOError) and getattr(error, "errno", None) == errno.EPIPE:
                # Ignore Broken Pipe
                # While in python3 we can directly catch 'BrokenPipeError', in python2 it doesn't exist.

                # Python flushes standard streams on exit; redirect remaining output
                # to devnull to avoid another BrokenPipeError at shutdown
                devnull = os.open(os.devnull, os.O_WRONLY)
                os.dup2(devnull, sys.stdout.fileno())
                return SUCCESS
            logger.debug(traceback.format_exc())
            logger.error(error)
            contact = config_get("policy", "support", raise_exception=False)
            support = ("If it's a problem concerning your experiment or if you're unsure what to do, please follow up at: %s\n" % contact) if contact else ""
            contact = config_get("policy", "support_rucio", default="https://github.com/rucio/rucio/issues")
            support += "If you're sure there is a problem with Rucio itself, please follow up at: " + contact
            logger.error("\nRucio exited with an unexpected/unknown error.\n" 'Please rerun the last command with the "-v" option to gather more information.\n' "%s" % support)
            return FAILURE

    return new_funct


def get_client(args, logger):
    """
    Returns a new client object.
    """
    if hasattr(args, "config") and (args.config is not None):
        os.environ["RUCIO_CONFIG"] = args.config

    if logger is None:
        logger = setup_logger(module_name=__name__, logger_name="user", verbose=args.verbose)

    if not args.auth_strategy:
        if "RUCIO_AUTH_TYPE" in os.environ:
            auth_type = os.environ["RUCIO_AUTH_TYPE"].lower()
        else:
            try:
                auth_type = config_get("client", "auth_type").lower()
            except (NoOptionError, NoSectionError):
                logger.error("Cannot get AUTH_TYPE")
                sys.exit(1)
    else:
        auth_type = args.auth_strategy.lower()

    if auth_type == "userpass" and args.username is not None and args.password is not None:
        creds = {"username": args.username, "password": args.password}
    elif auth_type == "oidc":
        if args.oidc_issuer:
            args.oidc_issuer = args.oidc_issuer.lower()
        creds = {
            "oidc_scope": args.oidc_scope,
            "oidc_audience": args.oidc_audience,
            "oidc_polling": args.oidc_polling,
            "oidc_refresh_lifetime": args.oidc_refresh_lifetime,
            "oidc_issuer": args.oidc_issuer
        }
    elif auth_type == "x509":
        creds = {"client_cert": args.certificate, "client_key": args.client_key}
    else:
        creds = None

    try:
        client = Client(rucio_host=args.host, auth_host=args.auth_host, account=args.issuer, auth_type=auth_type, creds=creds, ca_cert=args.ca_certificate, timeout=args.timeout, user_agent=args.user_agent, vo=args.vo, logger=logger)
    except CannotAuthenticate as error:
        logger.error(error)
        if "alert certificate expired" in str(error):
            logger.error("The server certificate expired.")
        elif auth_type.lower() == "x509_proxy":
            logger.error("Please verify that your proxy is still valid and renew it if needed.")
        sys.exit(1)
    return client


def signal_handler(sig, frame, logger):
    logger.warning("You pressed Ctrl+C! Exiting gracefully")
    child_processes = subprocess.Popen("ps -o pid --ppid %s --noheaders" % os.getpid(), shell=True, stdout=subprocess.PIPE)
    child_processes = child_processes.stdout.read()  # type: ignore
    for pid in child_processes.split("\n")[:-1]:  # type: ignore
        try:
            os.kill(int(pid), signal.SIGTERM)
        except Exception:
            print("Cannot kill child process")
    sys.exit(1)


def setup_gfal2_logger():
    gfal2_logger = logging.getLogger("gfal2")
    gfal2_logger.setLevel(logging.CRITICAL)
    gfal2_logger.addHandler(logging.StreamHandler())


class Arguments(dict):
    """dot.notation access to dictionary attributes"""

    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


class JSONType(click.ParamType):
    name = "json"

    def convert(
            self,
            value: Union[str, None],
            param: "Optional[click.Parameter]",
            ctx: "Optional[click.Context]",
    ) -> Optional[dict]:
        if value is None:
            return None

        try:
            return json.loads(value)
        except json.JSONDecodeError as e:
            self.fail(f"Invalid JSON: {e}", param, ctx)


def scope_exists(client: 'Client', scope: str) -> None:
    possible_scopes = client.list_scopes()
    if not len(list(possible_scopes)):
        raise ScopeNotFound
    if isinstance(list(possible_scopes)[0], str):  # TODO Backwards Compat - Remove in future releases - #8125
        scopes = possible_scopes
    else:
        scopes = [s['scope'] for s in possible_scopes]  # type: ignore

    if scope not in scopes:  # type: ignore - handled by the if isinstance
        raise ScopeNotFound


def get_scope(did: str, client: Client) -> tuple[str, str]:
    try:
        scope, name = extract_scope(did)
        return scope, name
    except TypeError:
        known_scopes = client.list_scopes()
        if not len(list(known_scopes)):
            raise ScopeNotFound
        if isinstance(known_scopes, dict):
            scopes = known_scopes.get('scope')  # type: ignore - does not accept 'scope' as a Literal['scope']
            scope, name = extract_scope(did, scopes)
        elif isinstance(known_scopes, list):
            scope, name = extract_scope(did, known_scopes)  # type: ignore - Handled by the isinstance
        else:
            raise ScopeNotFound

        return scope, name


class RichCLITheme:
    """
    Class to define styles for Rich widgets and prints in the CLI.
    """
    TABLE_FMT = box.SQUARE

    TEXT_HIGHLIGHT = 'grey50'  # Used to highlight prints between tables, e.g. get_metadata or stat.
    SUBHEADER_HIGHLIGHT = 'cyan'  # Used to highlight prints between tables for a section, e.g. protocols or usage per account.
    SPINNER = 'dots2'
    SPINNER_STYLE = 'green'

    JSON_STR = 'green'
    JSON_NUM = 'bold cyan'

    SUCCESS_ICON = '[bold green]\u2714[/]'
    FAILURE_ICON = '[bold red]\u2717[/]'

    LOG_THEMES = {
        'logging.level.info': 'default',
        'logging.level.warning': 'bold yellow',
        'logging.level.debug': 'dim',
        'logging.level.critical': 'default on red',
        'repr.bool_true': 'green',
        'repr.bool_false': 'red',
        'log.time': 'turquoise4'
    }

    DID_TYPE = {
        'CONTAINER': 'bold dodger_blue1',
        'DATASET': 'bold orange3',
        'FILE': 'bold default',
        'COLLECTION': 'bold green',
        'ALL': 'bold magenta',
        'DERIVED': 'bold magenta'
    }

    BOOLEAN = {
        'True': 'green',
        'False': 'red'
    }

    RULE_STATE = {
        'OK': 'bold green',
        'REPLICATING': 'bold default',
        'STUCK': 'bold orange3',
        'WAITING APPROVAL': 'bold dodger_blue1',
        'INJECT': 'bold medium_purple3',
        'SUSPENDED': 'bold red'
    }

    RSE_TYPE = {
        'DISK': 'bold dodger_blue1',
        'TAPE': 'bold orange3',
        'UNKNOWN': 'bold'
    }

    SUBSCRIPTION_STATE = {
        'ACTIVE': 'bold green',
        'INACTIVE': 'bold',
        'NEW': 'bold dodger_blue1',
        'UPDATED': 'bold green',
        'BROKEN': 'bold red',
        'UNKNOWN': 'bold orange3'
    }

    AVAILABILITY = {
        'AVAILABLE': 'bold green',
        'DELETED': 'bold',
        'LOST': 'bold red',
        'UNKNOWN': 'bold orange3'
    }

    ACCOUNT_STATUS = {
        'ACTIVE': 'bold green',
        'SUSPENDED': 'bold red',
        'DELETED': 'bold'
    }

    REPLICA_STATE = {
        'A': 'bold green',
        'U': 'bold red',
        'C': 'bold default',
        'B': 'bold dodger_blue1',
        'D': 'bold red',
        'T': 'bold orange3'
    }

    ACCOUNT_TYPE = {
        'USER': 'default',
        'GROUP': 'medium_purple3',
        'SERVICE': 'yellow'
    }

    OPENDATA_DID_STATE = {
        'PUBLIC': 'bold green',
        'DRAFT': 'bold default',
        'SUSPENDED': 'bold red',
    }


class RichUtils:
    # Collection of utility functions for the Rich CLI.
    MIN_CONSOLE_WIDTH = 80
    MAX_TRACEBACK_WIDTH = 120  # Slightly higher than default width of rich.traceback (100).

    @staticmethod
    def setup_rich_logger(
        module_name: Optional[str] = None,
        logger_name: Optional[str] = None,
        logger_level: Optional[int] = None,
        verbose: bool = False,
        console: Optional[Console] = None
    ) -> logging.Logger:
        """
        Factory method to set logger with RichHandler.

        The function is a copy of the method in rucio.common.utils setup_logger() with minor changes.

        :param module_name: __name__ of the module that is calling this method
        :param logger_name: name of the logger, typically name of the module.
        :param logger_level: if not given, fetched from config.
        :param verbose: verbose option set in bin/rucio
        :param console: Rich console object
        :returns: logger with RichHandler
        """
        # Helper method for cfg check.
        def _force_cfg_log_level(cfg_option: str) -> bool:
            cfg_forced_modules = config_get('logging', cfg_option, raise_exception=False, default=None, clean_cached=True, check_config_table=False)
            if cfg_forced_modules and module_name is not None:
                if re.match(str(cfg_forced_modules), module_name):
                    return True
            return False

        if not logger_name:
            if not module_name:
                logger_name = 'user'
            else:
                logger_name = module_name.split('.')[-1]
        logger = logging.getLogger(logger_name)

        # Extracting the log level.
        if not logger_level:
            logger_level = logging.INFO
            if verbose:
                logger_level = logging.DEBUG

            # Overriding by the config.
            cfg_levels = (logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR)
            for level in cfg_levels:
                cfg_opt = 'forceloglevel' + logging.getLevelName(level)
                if _force_cfg_log_level(cfg_opt):
                    logger_level = level

        logger.setLevel(logger_level)

        def add_handler(logger: logging.Logger,
                        console: Optional[Console] = None,
                        verbose: bool = False) -> None:

            def time_formatter(timestamp: datetime) -> Text:
                return Text(f"[{timestamp.isoformat(sep=' ', timespec='milliseconds')}]")

            console = console or Console()
            handler = RichHandler(rich_tracebacks=True, markup=True, show_path=verbose, show_time=verbose, console=console, tracebacks_width=min(console.width, RichUtils.MAX_TRACEBACK_WIDTH),
                                tracebacks_word_wrap=True, log_time_format=time_formatter)
            logger.addHandler(handler)

        # Setting handler and formatter.
        if not logger.handlers:
            add_handler(logger, console, verbose)

        return logger

    @staticmethod
    def _format_value(value: Optional[Union[RenderableType, int, float, bool, datetime]] = None) -> RenderableType:
        """
        Formats the value based on its type for Rich Table.

        A helper function to format the value to Rich RenderableType.

        :param value: value to format
        :returns: formatted value
        """
        if value is None or str(value) == 'None':
            return ''
        if isinstance(value, bool):
            return Text(str(value), style=RichCLITheme.BOOLEAN[str(value)])
        if isinstance(value, (int, float, datetime)):
            return str(value)
        return value

    @staticmethod
    def generate_table(
        rows: 'Sequence[Sequence[Union[RenderableType, int, float, bool, datetime]]]',
        headers: Optional['Sequence[RenderableType]'] = None,
        row_styles: Optional['Sequence[StyleType]'] = None,
        col_alignments: Optional[list[JustifyMethod]] = None,
        table_format: box.Box = RichCLITheme.TABLE_FMT,
    ) -> Table:
        """
        Generates a Rich Table object from given input rows.

        The elements in each row can be either plain strings or Rich renderable objects.
        Passing strings will display them as simple text, while using Rich objects
        allows you to introduce additional structure, styling, and widgets (e.g. Text, Trees) into
        the table. Strings with style markup will be rendered as styled text.

        :param table_format: style of the table
        :param headers: list of headers
        :param rows: list of rows
        :param col_alignments: list of column alignments
        :param row_styles: list of row styles
        :returns: a Rich Table object
        """
        table = Table(box=table_format, show_header=headers is not None and len(headers) > 0)
        table.row_styles = row_styles or ['none', 'dim']

        if len(rows) == 0:
            if headers:
                for header in headers:
                    table.add_column(header)
            return table

        # Auto-detect on first row, numerical values on the right.
        col_alignments = col_alignments or ['right' if str(col).isnumeric() else 'left' for col in rows[0]]
        headers = headers or [''] * len(rows[0])
        while len(headers) > len(col_alignments):
            col_alignments.append('left')

        for header, alignment in zip(headers, col_alignments):
            table.add_column(header, overflow='fold', justify=alignment)

        for row in rows:
            row = [RichUtils._format_value(col) for col in row]
            table.add_row(*row)
        return table

    @staticmethod
    def print_output(
        *output: Any,
        console: Console,
        no_pager: bool = False
    ) -> None:
        """
        Prints the objects using the specified Rich console object. Optionally disables the pager if specified.

        The function works similarly to Rich's `console.print()` method but provides additional control over the pager feature.

        :param output: objects to print to the terminal
        :param console: Rich console object
        :param no_pager: flag to disable the pager
        """
        if console.is_terminal:
            if no_pager:
                console.print(*output)
            else:
                console.width = sys.maxsize   # Overwrite auto-detected console width.
                console.begin_capture()
                console.print(*output)
        else:
            console.width = sys.maxsize
            console.print(*output)

    @staticmethod
    def get_cli_config() -> str:
        """
        Returns the CLI type from the config file.

        :returns: CLI type (Rich or tabulate)
        """
        cli_type = config_get('experimental', 'cli', raise_exception=False, default='tabulate').lower()
        if cli_type not in ['rich', 'tabulate']:
            cli_type = 'tabulate'
        return cli_type

    @staticmethod
    def get_pager() -> 'Callable[[str], None]':
        """
        Returns the pager function based on the terminal availability.

        :returns: pager
        """
        default_pager = 'less'
        # Attempt to use the default pager if available.
        if shutil.which(default_pager) is not None:
            return lambda text: pydoc.pipepager(text, f'{default_pager} -FRSXKM')

        # Fall back to pydoc.pager if the default pager is not available.
        return pydoc.pager
