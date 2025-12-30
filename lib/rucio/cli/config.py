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
from rucio.client.configclient import ConfigClient
from rucio.common.exception import ConfigNotFound, AccessDenied

@click.group()
def config():
    """
    Configuration management.
    """
    pass

@config.command()
@click.argument('section')
@click.argument('option', required=False)
def get(section, option):
    """
    Get a configuration value.
    """
    client = ConfigClient()
    try:
        value = client.get_config(section, option)
        if option:
            print(value)
        else:
            for k, v in value.items():
                print(f"{k} = {v}")
    except ConfigNotFound:
        print("Configuration not found.")
    except Exception as e:
        print(f"Error: {e}")

@config.command()
@click.argument('section')
@click.argument('option')
@click.argument('value')
def set(section, option, value):
    """
    Set a configuration value.
    """
    client = ConfigClient()
    try:
        client.set_config(section, option, value)
        print("Configuration set.")
    except AccessDenied:
        print("Access denied: You do not have permission to set configuration.")
    except Exception as e:
        print(f"Error: {e}")

@config.command()
@click.argument('section')
@click.argument('option')
def delete(section, option):
    """
    Delete a configuration value.
    """
    client = ConfigClient()
    try:
        client.delete_config(section, option)
        print("Configuration deleted.")
    except AccessDenied:
        print("Access denied: You do not have permission to delete configuration.")
    except Exception as e:
        print(f"Error: {e}")
