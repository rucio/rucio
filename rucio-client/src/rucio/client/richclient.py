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
import pydoc
import re
import subprocess
import sys
from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional, Union

from rich import box
from rich.console import Console, JustifyMethod, RenderableType
from rich.logging import RichHandler
from rich.table import Table
from rich.text import Text

from rucio.core.common.config import config_get

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from rich.style import StyleType


MIN_CONSOLE_WIDTH = 80
MAX_TRACEBACK_WIDTH = 120  # Slightly higher than default width of rich.traceback (100).


class CLITheme:
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


def setup_rich_logger(
    module_name: Optional[str] = None,
    logger_name: Optional[str] = None,
    logger_level: Optional[int] = None,
    verbose: bool = False,
    console: Optional[Console] = None
) -> logging.Logger:
    """
    Factory method to set logger with RichHandler.

    The function is a copy of the method in rucio.core.common.utils setup_logger() with minor changes.

    :param module_name: __name__ of the module that is calling this method
    :param logger_name: name of the logger, typically name of the module.
    :param logger_level: if not given, fetched from config.
    :param verbose: verbose option set in rucio-cli-client/rucio
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
        handler = RichHandler(rich_tracebacks=True, markup=True, show_path=verbose, show_time=verbose, console=console, tracebacks_width=min(console.width, MAX_TRACEBACK_WIDTH),
                              tracebacks_word_wrap=True, log_time_format=time_formatter)
        logger.addHandler(handler)

    # Setting handler and formatter.
    if not logger.handlers:
        add_handler(logger, console, verbose)

    return logger


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
        return CLITheme.BOOLEAN[str(value)]
    if isinstance(value, (int, float, datetime)):
        return str(value)
    return value


def generate_table(
    rows: 'Sequence[Sequence[Union[RenderableType, int, float, bool, datetime]]]',
    headers: Optional['Sequence[RenderableType]'] = None,
    row_styles: Optional['Sequence[StyleType]'] = None,
    col_alignments: Optional[list[JustifyMethod]] = None,
    table_format: box.Box = CLITheme.TABLE_FMT,
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
        row = [_format_value(col) for col in row]
        table.add_row(*row)
    return table


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


def get_cli_config() -> str:
    """
    Returns the CLI type from the config file.

    :returns: CLI type (Rich or tabulate)
    """
    cli_type = config_get('experimental', 'cli', raise_exception=False, default='tabulate').lower()
    if cli_type not in ['rich', 'tabulate']:
        cli_type = 'tabulate'
    return cli_type


def get_pager() -> 'Callable[[str], None]':
    """
    Returns the pager function based on the terminal availability.

    :returns: pager
    """
    default_pager = 'less'
    try:
        result = subprocess.run([default_pager], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        less_available = result.returncode == 0
    except Exception:
        less_available = False

    def less_pager_function(text: str) -> None:
        """Use the 'less' pager with -FRSXKM options."""
        pydoc.pipepager(text, f'{default_pager} -FRSXKM')

    if less_available:
        return less_pager_function
    return pydoc.pager
