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
from abc import abstractmethod
from argparse import ArgumentParser, Namespace
from typing import Type, TypeVar


_Self = TypeVar('_Self')


class Program:

    @classmethod
    def setup_parser(cls, parser: ArgumentParser) -> None:
        """Register the subprogram arguments with the parser."""
        cls._add_arguments(parser)
        parser.set_defaults(init_program=cls.init_program)

    @classmethod
    @abstractmethod
    def init_program(cls: Type[_Self], args: Namespace) -> _Self:
        """Initializes the subprogram from the passed arguments."""

    @classmethod
    @abstractmethod
    def _add_arguments(cls, parser: ArgumentParser) -> None:
        """Adds the program specific arguments to the parser."""

    @abstractmethod
    def run(self) -> int:
        """Runs the program and returns the process exit-code."""
