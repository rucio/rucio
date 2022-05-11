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

import os
from pathlib import Path

# GeoLite2-City-Test.mmdb downloaded on 26/Jan/2022 from ./test-data/ in
# https://github.com/maxmind/MaxMind-DB/tree/2f0ef0249245c7f19feffa366793a6fffd529701/
# Check ./source-data/GeoLite2-City-Test.json in this repository for IPs to use in tests
GEOIP_LITE2_CITY_TEST_DB = Path(os.path.abspath(__file__)).parent / 'GeoLite2-City-Test.tar.gz'
