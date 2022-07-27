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
import os
import subprocess
import tempfile
from pathlib import Path

from .generate import GenerateProgram, run_pyright
from .models import ReportDict


def _run(cmd: str) -> str:
    proc = subprocess.run(cmd.split(' '), stdout=subprocess.PIPE)
    return proc.stdout.decode('utf-8')


def run_pyright_for_commit(commit: str, config: Path, silent: bool) -> ReportDict:
    config = config.absolute()
    cwd = os.getcwd()
    with tempfile.TemporaryDirectory() as tmpdir:
        _run(f'git worktree add -d {tmpdir} {commit}')
        os.chdir(tmpdir)
        report = run_pyright(config, silent)
        os.chdir(cwd)
        _run(f'git worktree remove --force {tmpdir}')
    return report


class GenerateForCommitProgram(GenerateProgram):

    @staticmethod
    def setup_parser(parser: ArgumentParser) -> None:
        GenerateProgram.setup_parser(parser)
        parser.description = """
        Invokes Pyright to generate a report for the given commit.
        """
        parser.add_argument('commit', help='The commit to generate the report for.')

    @classmethod
    def init_program(cls, args: Namespace):
        out = args.out
        commit = args.commit
        config = args.config
        return cls(out, commit, config)

    def __init__(self, out: Path, commit: str, config: Path):
        super().__init__(out, config)
        self.commit = commit

    def generate_report(self) -> ReportDict:
        return run_pyright_for_commit(self.commit, self.config, silent=False)
