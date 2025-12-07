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

from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING

from .models import Report, ReportDiagnostic, ReportDiagnosticWithoutRange, Severity
from .utils import group_by, load_json

if TYPE_CHECKING:
    from argparse import ArgumentParser, Namespace


def setup_parser(parser: 'ArgumentParser') -> None:
    parser.description = """
    Compares two Pyright reports and outputs newly introduced warnings and errors.

    If new errors are introduced (or warnings with --Werror) the exit code is 2,
    otherwise 0.
    """
    parser.add_argument('old', type=Path, help='First report of comparison.')
    parser.add_argument('new', type=Path, help='Second report of comparison.')
    parser.add_argument('--Werror', action='store_true', help='Treat warnings as errors.')
    parser.set_defaults(func=compare)


def compare(args: 'Namespace') -> int:
    """Compares two reports to find new warnings and errors."""
    old_report = Report.from_dict(load_json(args.old))
    new_report = Report.from_dict(load_json(args.new))
    new_diagnostics = _compare_reports(new_report, old_report)

    print_regressions(new_diagnostics, new_report)

    num_errors = sum(count for err, count in new_diagnostics if err.severity == Severity.ERROR)
    num_warnings = sum(count for err, count in new_diagnostics if err.severity == Severity.WARNING)

    print('Summary:')
    print(f'    {num_errors} new errors.')
    print(f'    {num_warnings} new warnings.')

    if args.Werror:
        num_errors += num_warnings

    return 2 if num_errors else 0


def _compare_reports(new_report: Report, old_report: Report):
    """Counts instances of each diagnostic and returns those which have increased in the latest report."""
    old_count = Counter(map(ReportDiagnostic.without_range, old_report.diagnostics))
    new_count = Counter(map(ReportDiagnostic.without_range, new_report.diagnostics))

    diff = new_count
    diff.subtract(old_count)

    new_diagnostics = [(err, count) for err, count in diff.most_common() if count > 0]
    return new_diagnostics


def _indent(text: str, prefix: str) -> str:
    """Prepends `prefix` to each line in `text` except the first."""
    return text.replace('\n', '\n' + prefix)


def print_regressions(collection: list[tuple[ReportDiagnosticWithoutRange, int]], report: Report) -> None:
    """Takes the output of `_compare_reports` and prints it in a human-readable way."""
    all_problems = group_by(report.diagnostics, key=lambda elem: elem.without_range())
    diagnostics_by_file = group_by(collection, key=lambda elem: elem[0].file)

    for file, diagnostics in diagnostics_by_file.items():
        num_diagnostics = sum(count for _, count in diagnostics)
        print(f'Found {num_diagnostics} new problems in {file}')
        for diagnostic, count in diagnostics:
            candidate_line_list: list[str] = []
            for candidate in all_problems.get(diagnostic, []):
                if candidate.range_start_line == candidate.range_end_line:
                    candidate_line_list.append(f'{candidate.range_start_line + 1}')
                else:
                    candidate_line_list.append(f'{candidate.range_start_line + 1}-{candidate.range_end_line + 1}')

            prefix = f'  - {count} {diagnostic.severity.value}s with message'
            message = _indent(diagnostic.message, ' ' * (len(prefix) + 4))
            candidate_lines = ', '.join(candidate_line_list)

            print(f'{prefix} """{message}""".')
            print(f'    Candidates: line {candidate_lines}')
