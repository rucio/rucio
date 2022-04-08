#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright CERN since 2015
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

import sys
import os.path
base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_path)
os.chdir(base_path)

from hashlib import md5  # noqa: E402
from re import sub  # noqa: E402
from sys import argv  # noqa: E402


files = ['/static/rucio.js', '/static/base.js', '/static/rucio.css']


def md5_file(filename):
    hash_ = md5()
    with open(filename) as f:
        for chunk in iter(lambda: f.read(4096), ""):
            hash_.update(chunk)
    return hash_.hexdigest()


with open(argv[1], 'r') as f:
    orig_file = f.read()

new_file = orig_file

for f in files:
    md5_sum = md5_file('/opt/rucio/lib/rucio/web/ui' + f)
    regex = r"(?<=" + f + r"\?version=)[^\"]+"

    new_file = sub(regex, md5_sum, new_file)

with open(argv[1], 'w') as f:
    f.write(new_file)
