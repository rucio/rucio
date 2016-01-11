#!/bin/bash
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2015
# Mario Lassnig, <mario.lassnig@cern.ch>, 2014
# Martin Barisits, <martin.barisits@cern.ch>, 2016

/bin/cp README.rucio.rst README.rst
/bin/cp MANIFEST.in.rucio MANIFEST.in
# Pre-build one time to ensure correct vcversion file
python setup.py --release build sdist
# Push on pypi@org
python setup_rucio.py --release register sdist upload


/bin/cp README.client.rst README.rst
/bin/cp MANIFEST.in.client MANIFEST.in
# Push on pypi@org
python setup_rucio_client.py  --release register sdist upload


/bin/cp README.webui.rst README.rst
/bin/cp MANIFEST.in.webui MANIFEST.in
# Push on pypi@org
python setup_webui.py register sdist upload

