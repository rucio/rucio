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

from rucio.cli.bin_legacy.rucio import add_lifetime_exception
from rucio.cli.utils import Arguments


@click.group()
def lifetime_exception():
    """Interact with the lifetime exception model"""


@lifetime_exception.command("add")
@click.option("-f", "--input-file", help="File where the list of datasets requested to be extended are located")
@click.option("--reason", help="The reason for the extension")
@click.option("-x", "--expiration", help="The expiration date format YYYY-MM-DD")
@click.pass_context
def add_(ctx, input_file, reason, expiration):
    """Add an exception to the lifetime model"""  # TODO description of what this does
    args = Arguments({"inputfile": input_file, "reason": reason, "expiration": expiration})
    add_lifetime_exception(args, ctx.obj.client, ctx.obj.logger, ctx.obj.console, ctx.obj.spinner)
