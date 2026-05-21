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

from rich.console import Console

from rucio.client.richclient import generate_table


def test_generate_table_renders_boolean_values() -> None:
    console = Console(record=True, color_system=None, width=80)

    console.print(generate_table([['admin', True], ['suspended', False]], headers=['Key', 'Value']))

    output = console.export_text()
    assert 'True' in output
    assert 'False' in output
    assert 'green' not in output
    assert 'red' not in output
