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
import importlib
import signal
import time

import click
from rich.console import Console
from rich.status import Status
from rich.theme import Theme
from rich.traceback import install

from rucio import version
from rucio.cli.bin_legacy.rucio import ping, test_server, whoami_account
from rucio.cli.utils import Arguments, exception_handler, get_client, setup_gfal2_logger, signal_handler
from rucio.client.richclient import MAX_TRACEBACK_WIDTH, MIN_CONSOLE_WIDTH, CLITheme, get_cli_config, get_pager, setup_rich_logger
from rucio.common.utils import setup_logger


# Taken directly from https://click.palletsprojects.com/en/stable/complex/#defining-the-lazy-group
class LazyGroup(click.Group):
    def __init__(self, *args, lazy_subcommands=None, **kwargs):
        super().__init__(*args, **kwargs)
        # lazy_subcommands is a map of the form:
        #
        #   {command-name} -> {module-name}.{command-object-name}
        #
        self.lazy_subcommands = lazy_subcommands or {}

    def list_commands(self, ctx):
        base = super().list_commands(ctx)
        lazy = sorted(self.lazy_subcommands.keys())
        return base + lazy

    def get_command(self, ctx, cmd_name):
        if cmd_name in self.lazy_subcommands:
            return self._lazy_load(cmd_name)
        return super().get_command(ctx, cmd_name)

    def _lazy_load(self, cmd_name):
        # lazily loading a command, first get the module name and attribute name
        import_path = self.lazy_subcommands[cmd_name]
        modname, cmd_object_name = import_path.rsplit(".", 1)
        # do the import
        mod = importlib.import_module(modname)
        # get the Command object from that module
        cmd_object = getattr(mod, cmd_object_name)
        # check the result to make debugging easier
        if not isinstance(cmd_object, click.BaseCommand):
            raise ValueError(f"Lazy loading of {import_path} failed by returning " "a non-command object")
        return cmd_object


@click.group(
    cls=LazyGroup,
    lazy_subcommands={
        "account": "rucio.cli.account.account",
        "config": "rucio.cli.config.config",
        "did": "rucio.cli.did.did",
        "download": "rucio.cli.download.download",
        "lifetime-exception": "rucio.cli.lifetime_exception.lifetime_exception",
        "replica": "rucio.cli.replica.replica",
        "rse": "rucio.cli.rse.rse",
        "rule": "rucio.cli.rule.rule",
        "scope": "rucio.cli.scope.scope",
        "subscription": "rucio.cli.subscription.subscription",
        "upload": "rucio.cli.upload.upload_command",
        "opendata": "rucio.cli.opendata.opendata",
    },
    context_settings={"help_option_names": ["-h", "--help"]}
)  # TODO: Implement https://click.palletsprojects.com/en/stable/options/#dynamic-defaults-for-prompts for args from config or os
@click.option("--account", "--issuer", "issuer", help="Rucio account to use.")
@click.option("--auth-host", help="The Rucio Authentication host")
@click.option("-S", "--auth-strategy", help="Authentication strategy", type=click.Choice(['userpass', 'x509', 'x509_proxy', 'gss', 'ssh', 'saml', 'oidc']))
# x509 and x509 proxy auth
@click.option("--ca-certificate", help="CA certificate to verify peer against (SSL)")
@click.option("--certificate", help="Client certificate file")
@click.option("--client-key", help="Client key for x509 Authentication")
@click.option("--config", help="The Rucio configuration file to use")
@click.option("-H", "--host", help="The Rucio API host")
# oidc auth
@click.option("--oidc-user", help="OIDC username")
@click.option("--oidc-password", help="OIDC password")
@click.option("--oidc-audience", help="Defines which audience are tokens requested for.")
@click.option(
    "--oidc-auto",
    is_flag=True,
    default=False,
    help="""
        If not specified, username and password credentials are not required and users will be given a URL to use in their browser.
        If specified, the users explicitly trust Rucio with their IdP credentials"
    """,
)
@click.option(
    "--oidc-issuer",
    help="""
        Defines which Identity Provider is going to be used.
        The issuer string must correspond to the keys configured in the /etc/idpsecrets.json auth server configuration file")
    """,
)
@click.option(
    "--oidc-polling",
    is_flag=True,
    default=False,
    help="""
        If not specified, user will be asked to enter a code returned by the browser to the command line.
        If --polling is set, Rucio Client should get the token without any further interaction of the user.
        This option is active only if --auto is *not* specified
    """,
)
@click.option(
    "--oidc-refresh-lifetime",
    help="""
        Max lifetime in hours for this access token; the token will be refreshed by an asynchronous Rucio daemon.
        If not specified, refresh will be stopped after 4 days.
        This option is effective only if --oidc-scope includes offline_access scope for a refresh token to be granted to Rucio
    """,
)
@click.option(
    "--oidc-scope",
    default="openid profile",
    help="""
        Defines which (OIDC) information user will share with Rucio. Rucio requires at least -sc='openid profile'.
        To request refresh token for Rucio, scope must include 'openid offline_access'
        and there must be no active access token saved on the side of the currently used Rucio Client,
    """,
)
@click.option("-T", "--timeout", type=float, help="Set all timeout values to seconds")
@click.option("-U", "--user-agent", default="rucio-clients", help="Rucio User Agent")
# userpass/gss/saml auth
@click.option("-u", "--user", help="Username for userpass")
@click.option("--password", help="Password for userpass")
@click.option("--vo", help="VO to authenticate at. Only used in multi-VO mode")
@click.option("-v", "--verbose", default=False, is_flag=True, help="Print more verbose output")
@click.version_option(version.version_string(), message="%(prog)s %(version)s")
# Hidden options at the end
@click.option("--no-pager", is_flag=True, default=False, hidden=True)
@exception_handler
@click.pass_context
def main(
    ctx,
    config,
    verbose,
    host,
    auth_host,
    issuer,
    auth_strategy,
    timeout,
    user_agent,
    vo,
    no_pager,
    user,
    password,
    oidc_user,
    oidc_password,
    oidc_scope,
    oidc_audience,
    oidc_auto,
    oidc_polling,
    oidc_refresh_lifetime,
    oidc_issuer,
    certificate,
    client_key,
    ca_certificate,
):
    ctx.ensure_object(Arguments)
    ctx.obj.start_time = time.time()
    ctx.obj.verbose = verbose

    use_rich = get_cli_config() == "rich"

    console = Console(theme=Theme(CLITheme.LOG_THEMES), soft_wrap=True)
    console.width = max(MIN_CONSOLE_WIDTH, console.width)
    spinner = Status("Initializing spinner", spinner=CLITheme.SPINNER, spinner_style=CLITheme.SPINNER_STYLE, console=console)

    ctx.obj.use_rich = use_rich
    ctx.obj.spinner = spinner
    ctx.obj.console = console
    ctx.obj.no_pager = no_pager
    ctx.obj.pager = get_pager()

    if use_rich:
        install(console=console, word_wrap=True, width=min(console.width, MAX_TRACEBACK_WIDTH))  # Make rich exception tracebacks the default.
        logger = setup_rich_logger(module_name=__name__, logger_name="user", verbose=verbose, console=console)
    else:
        logger = setup_logger(module_name=__name__, logger_name="user", verbose=verbose)
    args = Arguments(
        {
            "config": config,
            "host": host,
            "issuer": issuer,
            "auth_host": auth_host,
            "auth_strategy": auth_strategy,
            "timeout": timeout,
            "user_agent": user_agent,
            "VO": vo,
            "username": user,
            "password": password,
            "oidc_username": oidc_user,
            "oidc_password": oidc_password,
            "oidc_scope": oidc_scope,
            "oidc_audience": oidc_audience,
            "oidc_auto": oidc_auto,
            "oidc_polling": oidc_polling,
            "oidc_refresh_lifetime": oidc_refresh_lifetime,
            "oidc_issuer": oidc_issuer,
            "certificate": certificate,
            "client_key": client_key,
            "ca_certificate": ca_certificate,
        }
    )  # TODO Future improvement - change `get_client` to take these args directly
    client = get_client(args, logger)  # TODO Future improvement - use envvar functionality in click to remove conditionals checking env vars

    setup_gfal2_logger()
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, logger))

    ctx.obj.client = client
    ctx.obj.logger = logger

    ctx.call_on_close(_teardown)


@click.pass_context
def _teardown(ctx):
    time_elapsed = time.time() - ctx.obj.start_time

    if ctx.obj.use_rich:
        ctx.obj.spinner.stop()
    if ctx.obj.console.is_terminal and not ctx.obj.no_pager:
        command_output = ctx.obj.console.end_capture()
        if command_output == "" and ctx.obj.verbose:
            print("Completed in %-0.4f sec." % (time_elapsed))
        else:
            if ctx.obj.verbose:
                command_output += "Completed in %-0.4f sec." % (time_elapsed)
            # Ignore SIGINT during pager execution.
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            ctx.obj.pager(command_output)
    else:
        if ctx.obj.verbose:
            print("Completed in %-0.4f sec." % (time_elapsed))


@main.command(name="whoami", help="Get information about account whose token is used")
@click.pass_context
def exe_whoami(ctx):
    args = Arguments({"no_pager": ctx.obj.no_pager})
    whoami_account(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@main.command(name="ping", help="Ping Rucio server")
@click.pass_context
def exe_ping(ctx):
    args = Arguments({"no_pager": ctx.obj.no_pager})
    ping(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)


@main.command(name="test-server", help="Test client against the server")
@click.pass_context
def exe_test_server(ctx):
    args = Arguments({"no_pager": ctx.obj.no_pager})
    test_server(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)
