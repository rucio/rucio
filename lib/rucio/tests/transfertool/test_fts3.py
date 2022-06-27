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

from typing import List
from unittest.mock import Mock

import pytest

from rucio.common.utils import CHECKSUM_KEY, GLOBALLY_SUPPORTED_CHECKSUMS
from rucio.transfertool.fts3 import checksum_validation_strategy


@pytest.mark.parametrize(
    ('src_algos', 'dest_algos',
        'src_verify', 'dest_verify',
        'expected_direction', 'expected_algos'),
    (
        ('md5,adler32', 'md5,adler32', True, True,
            'both', {'md5', 'adler32'}),
        ('md5,adler32', '', True, True,
            'both', {'md5', 'adler32'}),
        ('', 'md5,adler32', True, True,
            'both', {'md5', 'adler32'}),
        # Reduced intersection
        ('md5,adler32', 'md5', True, True,
            'both', {'md5'}),
        # No intersection
        ('md5,adler32', 'none', True, True,
            'source', {'md5', 'adler32'}),
        ('none', 'md5,adler32', True, True,
            'destination', {'md5', 'adler32'}),
        # Prefer destination
        ('md5', 'adler32', True, True,
            'destination', {'adler32'}),
        # No checksumming
        ('none', 'none', True, True,
            'none', set()),
        ('md5', 'md5', False, False,
            'none', set()),
        # Correct default values
        ('', '', True, True,
            'both', set(GLOBALLY_SUPPORTED_CHECKSUMS)),
    )
)
def test_checksum_validation_strategy(
    src_algos: str, dest_algos: str,
    src_verify: bool, dest_verify: bool,
    expected_direction: str, expected_algos: List[str]
):
    src_attributes = {CHECKSUM_KEY: src_algos, 'verify_checksum': src_verify}
    dest_attributes = {CHECKSUM_KEY: dest_algos, 'verify_checksum': dest_verify}

    logger = Mock()
    direction, algos = checksum_validation_strategy(src_attributes, dest_attributes, logger)

    assert direction == expected_direction
    assert algos == expected_algos
