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

from datetime import datetime, timezone

import pytest
from rich.text import Text
from rich.tree import Tree

from rucio.client.richclient import CLITheme, _format_value


class TestRichClientFormatValue:

    @pytest.mark.parametrize("value", [True, False])
    def test_format_value_when_boolean_should_return_styled_text(self, value):
        cell = _format_value(value)
        assert isinstance(cell, Text)
        assert str(cell) == str(value)
        assert cell.style == CLITheme.BOOLEAN[str(value)]

    @pytest.mark.parametrize("value", [None, "None"])
    def test_format_value_when_none_should_not_fail(self, value):
        assert _format_value(value) == ''

    def test_format_value_when_empty_should_return_empty(self):
        assert _format_value("") == ""

    @pytest.mark.parametrize("value", [Text("blah"), Tree("blah")])
    def test_format_value_when_renderable_type_should_return_it(self, value):
        assert _format_value(value) is value

    @pytest.mark.parametrize("value", [3, 3.14])
    def test_format_value_when_number_should_return_string(self, value):
        assert _format_value(value) == str(value)

    def test_format_value_when_various_dates_should_return_string(self):
        assert _format_value(datetime(2012, 1, 1)) == "2012-01-01 00:00:00"
        assert _format_value(datetime(2012, 1, 1, 12, 30, 30, 123456)) == "2012-01-01 12:30:30.123456"
        assert _format_value(
            datetime(2012, 1, 1, 12, 30, 30, 123456, tzinfo=timezone.utc)
        ) == "2012-01-01 12:30:30.123456+00:00"
