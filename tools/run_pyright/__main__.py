#!/usr/bin/env python3
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

import sys
from argparse import ArgumentParser
from typing import Type

from .generate import GenerateProgram
from .generate_for_commit import GenerateForCommitProgram
from .compare import CompareProgram
from .compare_with_commit import CompareWithCommitProgram
from .program import Program


def parse_arguments():
    parser = ArgumentParser('tools/run_pyright.sh', description="Generate and compare Pyright typing reports.")
    subparser = parser.add_subparsers(dest='command')
    subparser.required = True

    def register(command: str, program: Type[Program]) -> None:
        program_parser = subparser.add_parser(command)
        program_parser.set_defaults(program=program.init_program)
        program.setup_parser(program_parser)

    register('generate', GenerateProgram)
    register('compare', CompareProgram)
    register('generate-for-commit', GenerateForCommitProgram)
    register('compare-with-commit', CompareWithCommitProgram)

    return parser.parse_args()


def main():
    args = parse_arguments()
    program: Program = args.program(args)
    exit_code = program.run()
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
