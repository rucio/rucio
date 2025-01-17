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

import json
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .models import Report
from .utils import save_json

if TYPE_CHECKING:
    from argparse import ArgumentParser, Namespace

def setup_parser(parser: 'ArgumentParser') -> None:
    parser.description = """
    Invokes Pyright to generate a report of current typing errors and warnings.
    """
    parser.add_argument('out', type=Path, help='Store the Pyright report at this path.')
    parser.set_defaults(func=generate)


def generate(args: 'Namespace') -> int:
    """Generate a Pyright report and save it at the specified path."""
    reportdict = _run_pyright()

    save_json(args.out, reportdict)

    report = Report.from_dict(reportdict)

    print('Summary:')
    print(f'    {report.summary.num_files} files checked.')
    print(f'    {report.summary.num_errors} errors.')
    print(f'    {report.summary.num_warnings} warnings.')
    print(f'    {report.summary.num_information} notes.')
    print(f'    Duration: {report.summary.time_seconds:.1f} seconds.')

    return 0


def _run_pyright() -> dict[str, Any]:
    """Runs the pyright type-checker and returns its output as json."""
    cmdline = ['pyright', '--outputjson', '.']
    try:
        process = subprocess.run(cmdline, stdout=subprocess.PIPE)
        return json.loads(process.stdout)
    except FileNotFoundError as ex:
        print('Error running pyright.'
              ' This could be due to pyright not being installed on your system,'
              ' in which case it may be installed using `npm install --global pyright`.\n'
              'Additional details:', ex,
              file=sys.stderr)
        sys.exit(1)
