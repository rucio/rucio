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

# Push on pypi@cern
/bin/cp setup_rucio.py setup.py
/bin/cp README.rucio.rst README.rst
/bin/cp MANIFEST.in.rucio MANIFEST.in
python setup.py --release register -r https://voatlasrucio-pip.cern.ch/ sdist upload -r https://voatlasrucio-pip.cern.ch/

/bin/cp setup_rucio_client.py setup.py
/bin/cp README.client.rst README.rst
/bin/cp MANIFEST.in.client MANIFEST.in
python setup.py --release register -r https://voatlasrucio-pip.cern.ch/ sdist upload -r https://voatlasrucio-pip.cern.ch/

# Push on pypi@org
/bin/cp setup_rucio.py setup.py
/bin/cp README.rucio.rst README.rst
/bin/cp MANIFEST.in.rucio MANIFEST.in
python setup.py --release register sdist upload

/bin/cp setup_rucio_client.py setup.py
/bin/cp README.client.rst README.rst
/bin/cp MANIFEST.in.client MANIFEST.in
python setup.py --release register sdist upload
/bin/cp setup_rucio.py setup.py