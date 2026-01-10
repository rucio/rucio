import click
from rucio.cli.bin_legacy.rucio_admin import get_config, set_config_option, delete_config_option
from rucio.cli.utils import Arguments

@click.group()
def config():
    """Configuration management."""
    pass

@config.command(name='get-config')
@click.option('--section', dest='section', help='Section name')
@click.option('--option', dest='option', help='Option name')
@click.pass_context
def get_config_cmd(ctx, **kwargs):
    args = Arguments(**kwargs)
    get_config(args, ctx.obj['client'], ctx.obj['logger'], ctx.obj['console'], ctx.obj['spinner'])

@config.command(name='set-config')
@click.option('--section', dest='section', required=True, help='Section name')
@click.option('--option', dest='option', required=True, help='Option name')
@click.option('--value', dest='value', required=True, help='Value')
@click.pass_context
def set_config_cmd(ctx, **kwargs):
    args = Arguments(**kwargs)
    set_config_option(args, ctx.obj['client'], ctx.obj['logger'], ctx.obj['console'], ctx.obj['spinner'])

@config.command(name='delete-config')
@click.option('--section', dest='section', required=True, help='Section name')
@click.option('--option', dest='option', required=True, help='Option name')
@click.pass_context
def delete_config_cmd(ctx, **kwargs):
    args = Arguments(**kwargs)
    delete_config_option(args, ctx.obj['client'], ctx.obj['logger'], ctx.obj['console'], ctx.obj['spinner'])
