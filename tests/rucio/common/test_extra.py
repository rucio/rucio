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
from unittest.mock import Mock, patch

from rucio.core.common.extra import import_extras


class TestExtra:
    @patch('rucio.common.extra.importlib')
    def test_import_extras(self, mock_importlib):
        mock_module = Mock()
        mock_importlib.import_module.return_value = mock_module
        assert import_extras(['module1']) == {'module1': mock_module}

    @patch('rucio.common.extra.importlib')
    def test_import_extras_importerror(self, mock_importlib):
        mock_importlib.import_module.side_effect = [ModuleNotFoundError, ImportError]
        assert import_extras(['module1', 'module2']) == {'module1': None, 'module2': None}
