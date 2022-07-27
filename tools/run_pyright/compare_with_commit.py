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

from .compare import CompareProgram
from .models import Report
from .generate import run_pyright
from .generate_for_commit import run_pyright_for_commit
from .utils import run_in_background


class CompareWithCommitProgram(CompareProgram):

    @staticmethod
    def setup_parser(parser: ArgumentParser) -> None:
        parser.description = """
        Generates Pyright reports for <commit> and the current working tree and compares them.

        If new errors (or warnings with --Werror) are introduced since <commit>,
        the exit code is 2, otherwise 0.
        """
        parser.add_argument('commit', help='The commit to compare with.')
        parser.add_argument('--Werror', action='store_true', help='Treat warnings as errors.')
        parser.add_argument('--silence-pyright', action='store_true', help='Suppress output from Pyright.')
        parser.add_argument('--config', type=Path, help='Optional Pyright config file to use.',
                            default=Path('pyrightconfig.json'))

    @classmethod
    def init_program(cls, args: Namespace):
        commit = args.commit
        werror = args.Werror
        config = args.config
        silence_pyright = args.silence_pyright
        return cls(commit, werror, config, silence_pyright)

    def __init__(self, commit: str, werror: bool, config: Path, silence_pyright: bool) -> None:
        self.commit = commit
        self.werror = werror
        self.config = config
        self.silence_pyright = silence_pyright

    def run(self) -> int:
        new_report_task = run_in_background(run_pyright,
                                            config=self.config,
                                            silent=self.silence_pyright)
        old_report_task = run_in_background(run_pyright_for_commit,
                                            self.commit,
                                            config=self.config,
                                            silent=self.silence_pyright)
        new_report = Report.from_dict(new_report_task()).relative_paths()
        old_report = Report.from_dict(old_report_task()).relative_paths()
        return self.compare_reports(old_report, new_report)
