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
from rucio.common.exception import AccessDenied

@click.group()
def config():
    """
    Configuration management.
    """
    pass

@config.command()
@click.argument('section')
@click.argument('option', required=False)
@click.pass_context
def get(ctx, section, option):
    """
    Get matching configuration.
    """
    client = ctx.obj['client']
    res = client.get_config(section=section, option=option)
    if not isinstance(res, dict):
        print('[%s]\n%s=%s' % (section, option, str(res)))
    else:
        print_header = True
        for i in list(res.keys()):
            if print_header:
                if section is not None:
                    print('[%s]' % section)
                else:
                    print('[%s]' % i)
            if not isinstance(res[i], dict):
                print('%s=%s' % (i, str(res[i])))
                print_header = False
            else:
                for j in list(res[i].keys()):
                    print('%s=%s' % (j, str(res[i][j])))

@config.command()
@click.argument('section')
@click.argument('option')
@click.argument('value')
@click.pass_context
def set(ctx, section, option, value):
    """
    Set matching configuration.
    """
    client = ctx.obj['client']
    client.set_config_option(section=section, option=option, value=value)
    print('Set configuration: %s.%s=%s' % (section, option, value))

@config.command()
@click.argument('section')
@click.argument('option')
@click.pass_context
def delete(ctx, section, option):
    """
    Delete matching configuration.
    """
    client = ctx.obj['client']
    if client.delete_config_option(section=section, option=option):
        print('Deleted section \'%s\' option \'%s\'' % (section, option))
    else:
        print('Section \'%s\' option \'%s\' not found' % (section, option))
