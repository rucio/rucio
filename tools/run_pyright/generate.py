# -*- coding: utf-8 -*-
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

from argparse import ArgumentParser, Namespace
from pathlib import Path
import json
import subprocess
import sys

from . import utils
from .models import ReportDict, Report
from .program import Program


def run_pyright(config: Path, silent: bool) -> ReportDict:
    """Runs the pyright type-checker and returns its output as json."""
    config = config.absolute()
    cmdline = ['pyright', '--project', str(config), '--outputjson']
    stderr = subprocess.DEVNULL if silent else None
    try:
        process = subprocess.run(cmdline, stdout=subprocess.PIPE, stderr=stderr)
        result = json.loads(process.stdout)
        result['rucio'] = {
            'root': str(config.parent)
        }
        return result
    except FileNotFoundError as ex:
        print('Error running pyright.'
              ' This could be due to pyright not being installed on your system,'
              ' in which case it may be installed using `npm install --global pyright`.\n'
              'Additional details:', ex,
              file=sys.stderr)
        sys.exit(1)


class GenerateProgram(Program):

    @staticmethod
    def setup_parser(parser: ArgumentParser) -> None:
        parser.description = """
        Invokes Pyright to generate a report of current typing errors and warnings.
        """
        parser.add_argument('out', type=Path, help='Store the Pyright report at this path.')
        parser.add_argument('--config', type=Path, help='Optional Pyright config file to use.',
                            default=Path('pyrightconfig.json'))

    @classmethod
    def init_program(cls, args: Namespace):
        """Generate a Pyright report and save it at the specified path."""
        out = args.out
        config = args.config
        return cls(out, config)

    def __init__(self, out: Path, config: Path):
        self.out = out
        self.config = config

    def run(self) -> int:
        reportdict = self.generate_report()
        self.save_report(reportdict)
        self.print_summary(reportdict)
        return 0

    def save_report(self, reportdict: ReportDict) -> None:
        utils.save_json(self.out, reportdict)

    def print_summary(self, reportdict: ReportDict) -> None:
        report = Report.from_dict(reportdict)
        print('Summary:')
        print(f'    {report.summary.num_files} files checked.')
        print(f'    {report.summary.num_errors} errors.')
        print(f'    {report.summary.num_warnings} warnings.')
        print(f'    {report.summary.num_information} notes.')
        print(f'    Duration: {report.summary.time_seconds:.1f} seconds.')

    def generate_report(self) -> ReportDict:
        return run_pyright(self.config, silent=False)
