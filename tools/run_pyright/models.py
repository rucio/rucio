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

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    ReportDict = dict[str, Any]


class Severity(Enum):
    INFORMATION = 'information'
    WARNING = 'warning'
    ERROR = 'error'


@dataclass(frozen=True)
class ReportDiagnosticWithoutRange:
    severity: Severity
    file: str
    rule: str
    message: str


@dataclass(frozen=True)
class ReportDiagnostic:
    severity: Severity
    file: str
    rule: str
    message: str
    range_start_line: int
    range_start_char: int
    range_end_line: int
    range_end_char: int

    @classmethod
    def from_dict(cls, obj: dict[str, Any]):
        file = obj.get('file')
        if file is None:
            file = obj.get('uri', {}).get('_filePath')
        return cls(
            severity=Severity(obj['severity']),
            file=file,
            rule=obj['rule'],
            message=obj['message'],
            range_start_line=obj['range']['start']['line'],
            range_start_char=obj['range']['start']['character'],
            range_end_line=obj['range']['end']['line'],
            range_end_char=obj['range']['end']['character'],
        )  # type: ignore

    def without_range(self) -> ReportDiagnosticWithoutRange:
        return ReportDiagnosticWithoutRange(
            self.severity, self.file, self.rule, self.message
        )  # type: ignore


@dataclass
class ReportSummary:
    num_files: int
    num_errors: int
    num_warnings: int
    num_information: int
    time_seconds: float

    @classmethod
    def from_dict(cls, obj: dict[str, Any]):
        return cls(
            num_files=obj['filesAnalyzed'],
            num_errors=obj['errorCount'],
            num_warnings=obj['warningCount'],
            num_information=obj['informationCount'],
            time_seconds=obj['timeInSec']
        )


@dataclass
class Report:
    summary: ReportSummary
    diagnostics: list[ReportDiagnostic]

    @classmethod
    def from_dict(cls, obj: 'ReportDict'):
        return cls(
            summary=ReportSummary.from_dict(obj['summary']),
            diagnostics=list(map(ReportDiagnostic.from_dict, obj['generalDiagnostics'])),
        )
