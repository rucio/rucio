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
from rucio.core.common.exception import RucioException


class TestRucioException:
    class MockException(RucioException):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._message = "Test exception."

    def test_rucio_exception_str(self):
        exc = self.MockException()
        assert str(exc) == "Test exception."

    def test_rucio_exception_str_extra_error_message(self):
        exc = self.MockException("Extra message.", "Second extra message.")
        assert str(exc) == "Test exception.\nDetails: Extra message.\nSecond extra message."
