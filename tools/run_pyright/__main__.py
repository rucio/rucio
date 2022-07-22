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
from argparse import ArgumentParser, Namespace
from typing import Callable

from . import generate
from . import compare


def parse_arguments():
    parser = ArgumentParser(description="Runs the pyright type checker.")
    subparser = parser.add_subparsers(dest='command')
    subparser.required = True
    func: Callable[[Namespace], int]

    parse_generate = subparser.add_parser('generate')
    func = generate.setup_parser(parse_generate)
    parse_generate.set_defaults(func=func)

    parse_compare = subparser.add_parser('compare')
    func = compare.setup_parser(parse_compare)
    parse_compare.set_defaults(func=func)

    return parser.parse_args()


def main():
    args = parse_arguments()
    exit_code = args.func(args)
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
