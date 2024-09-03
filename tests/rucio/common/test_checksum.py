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

from unittest.mock import Mock

import pytest

from rucio.common.checksum import GLOBALLY_SUPPORTED_CHECKSUMS, adler32, crc32, is_checksum_valid, md5, set_preferred_checksum, sha256
from rucio.common.exception import ChecksumCalculationError


class TestChecksumUtils:
    @pytest.mark.parametrize(
        'checksum,valid',
        [
            (GLOBALLY_SUPPORTED_CHECKSUMS[0], True),
            (Mock(), False)
        ]
    )
    def test_is_checksum_valid(self, checksum, valid):
        assert is_checksum_valid(checksum) == valid

    def test_set_preferred_checksum(self):
        mock_checksum = Mock()
        GLOBALLY_SUPPORTED_CHECKSUMS.append(mock_checksum)
        set_preferred_checksum(mock_checksum)

        # This is a global variable, so it must be imported here
        from rucio.common.checksum import PREFERRED_CHECKSUM

        assert PREFERRED_CHECKSUM == mock_checksum
        GLOBALLY_SUPPORTED_CHECKSUMS.pop()

    def test_set_preferred_checksum_not_valid(self):
        mock_checksum = Mock()
        set_preferred_checksum(mock_checksum)

        # This is a global variable, so it must be imported here
        from rucio.common.checksum import PREFERRED_CHECKSUM

        assert PREFERRED_CHECKSUM != mock_checksum


class TestChecksumCalculation:
    @pytest.fixture(scope="class")
    def test_file_to_checksum(self, tmp_path_factory):
        file = tmp_path_factory.mktemp('data') / 'file.txt'
        file.write_text('hello test\n')
        return file

    def test_md5(self, test_file_to_checksum):
        assert md5(test_file_to_checksum) == '31d50dd6285b9ff9f8611d0762265d04'

    def test_md5_no_file(self):
        with pytest.raises(ChecksumCalculationError) as e:
            md5('no_file')
        assert e.value.algorithm_name == 'md5'
        assert e.value.filepath == 'no_file'

    def test_adler32(self, test_file_to_checksum):
        assert adler32(test_file_to_checksum) == '198d03ff'

    def test_adler32_no_file(self):
        with pytest.raises(ChecksumCalculationError) as e:
            adler32('no_file')
        assert e.value.algorithm_name == 'adler32'
        assert e.value.filepath == 'no_file'

    def test_sha256(self, test_file_to_checksum):
        assert sha256(test_file_to_checksum) == 'd1b81a303d340fb689c6b6f4f474d9e04f314ed9ad8925686e4106452b53181b'

    def test_crc32(self, test_file_to_checksum):
        assert crc32(test_file_to_checksum) == 'C843500'
