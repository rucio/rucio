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
import click

from rucio.cli.utils import RichCLITheme, RichUtils
from rucio.common.utils import parse_response, render_json


@click.group(name='data')
def data():
    "Import and export data from Rucio."


@data.command(name='import')
@click.argument("file-path")
@click.pass_context
def exe_import(ctx: click.Context, file_path: str) -> None:
    """Import data from JSON file at [FILE-PATH] to Rucio."""
    import_file_path = file_path
    data = None
    if ctx.obj.use_rich:
        ctx.obj.spinner.update(status='Reading file')
        ctx.obj.spinner.start()

    try:
        with open(import_file_path) as import_file:
            data_string = import_file.read()
            data = parse_response(data_string)
    except ValueError as error:
        if ctx.obj.use_rich:
            ctx.obj.spinner.stop()
            RichUtils.print_output(f'{RichCLITheme.FAILURE_ICON} There was problem with decoding your file.', console=ctx.obj.console, no_pager=True)
            ctx.obj.logger.error(error)
        else:
            print('There was problem with decoding your file.')
            print(error)
        raise ValueError from error
    except OSError as error:
        if ctx.obj.use_rich:
            ctx.obj.spinner.stop()
            RichUtils.print_output(f'{RichCLITheme.FAILURE_ICON} There was a problem with reading your file.', console=ctx.obj.console, no_pager=True)
            ctx.obj.logger.error(error)
        else:
            print('There was a problem with reading your file.')
            print(error)
        raise OSError from error

    if data:
        ctx.obj.client.import_data(data)
        if ctx.obj.use_rich:
            ctx.obj.spinner.stop()
            RichUtils.print_output(f'{RichCLITheme.SUCCESS_ICON} Data successfully imported.', console=ctx.obj.console, no_pager=True)
        else:
            print('Data successfully imported.')
    else:
        if ctx.obj.cli_config == 'rich':
            ctx.obj.spinner.stop()
            RichUtils.print_output('Nothing to import.', console=ctx.obj.console, no_pager=True)
        else:
            print('Nothing to import.')
        raise ValueError


@data.command(name='export')
@click.pass_context
@click.argument("file-path")
def exe_export(ctx: click.Context, file_path: str) -> None:
    """Export data from Rucio to a JSON file at [FILE-PATH]"""
    destination_file_path = file_path
    if ctx.obj.use_rich:
        ctx.obj.spinner.update(status='Querying data')
        ctx.obj.spinner.start()
    else:
        print('Start querying data.')

    data = ctx.obj.client.export_data()
    try:
        with open(destination_file_path, 'w+') as destination_file:
            destination_file.write(render_json(**data))
            if ctx.obj.use_rich:
                print('File successfully written.')
        if ctx.obj.use_rich:
            ctx.obj.spinner.stop()
            RichUtils.print_output(f'{RichCLITheme.SUCCESS_ICON} Data successfully exported to {file_path}', console=ctx.obj.console, no_pager=True)
        else:
            print('Data successfully exported to %s' % file_path)
    except OSError as error:
        if ctx.obj.use_rich:
            ctx.obj.spinner.stop()
            RichUtils.print_output(f'{RichCLITheme.FAILURE_ICON} There was a problem with reading your file.', console=ctx.obj.console, no_pager=True)
            ctx.obj.logger.error(error)
        else:
            print('There was a problem with reading your file.')
            print(error)
        raise OSError from error
