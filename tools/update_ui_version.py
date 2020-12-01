#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2015
# - Martin Barisits, <martin.barisits@cern.ch>, 2019
# - Gabriele Gaetano Fronze' <gabriele.fronze@to.infn.it>, 2020
#
# script to update the version parameter for RucioUI Javascript and CSS includes

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
    hash = md5()
    with open(filename) as f:
        for chunk in iter(lambda: f.read(4096), ""):
            hash.update(chunk)
    return hash.hexdigest()


with open(argv[1], 'r') as f:
    orig_file = f.read()

new_file = orig_file

for f in files:
    md5_sum = md5_file('/opt/rucio/lib/rucio/web/ui' + f)
    regex = r"(?<=" + f + r"\?version=)[^\"]+"

    new_file = sub(regex, md5_sum, new_file)

with open(argv[1], 'w') as f:
    f.write(new_file)
