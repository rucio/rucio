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
import pytest

from lib.rucio.common.config import _convert_to_boolean, convert_to_any_type


class TestConversion:
    @pytest.mark.parametrize("value, expected", [
        ("true", True),
        ("TRUE", True),
        ("yes", True),
        ("on", True),
        ("false", False),
        ("FALSE", False),
        ("no", False),
        ("off", False),
        ("123", 123),
        ("-456", -456),
        ("3.14", 3.14),
        ("-2.718", -2.718),
        ("hello", "hello"),
        ("world", "world")
    ])
    def test_convert_to_any_type(self, value, expected):
        assert convert_to_any_type(value) == expected

    @pytest.mark.parametrize("value, expected", [
        (True, True),
        (False, False),
        ("true", True),
        ("yes", True),
        ("on", True),
        ("1", True),
        ("false", False),
        ("no", False),
        ("off", False),
        ("0", False),
        ("True", True),
        ("False", False),
        ("Yes", True),
        ("No", False),
        ("On", True),
        ("Off", False),
        ("TRUE", True),
        ("FALSE", False),
        ("YES", True),
        ("NO", False),
        ("ON", True),
        ("OFF", False)
    ])
    def test_convert_to_boolean(self, value, expected):
        assert _convert_to_boolean(value) == expected

    def test_convert_to_boolean_exception(self):
        with pytest.raises(ValueError, match="Not a boolean: invalid"):
            _convert_to_boolean("invalid")
