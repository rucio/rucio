#!/bin/bash
# Copyright 2012-2021 CERN
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
#
# Authors:
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2015
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014
# - Martin Barisits <martin.barisits@cern.ch>, 2015-2017
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2021

if [ "$#" -ne 1 ]; then
    echo "At least one of these arguments has to be specified:"
    echo "  all         Build all packages"
    echo "  rucio       Only build rucio core package"
    echo "  clients     Only build rucio clients package"
    echo "  webui       Only build rucio webui package"
    exit
fi

rucio=false
clients=false
webui=false

if [ "$1" == "all" ]; then
    rucio=true
    clients=true
    webui=true
    echo "Building ALL packages"
fi
if [ "$1" == "rucio" ]; then
    rucio=true
    echo "Building RUCIO package"
fi
if [ "$1" == "clients" ]; then
    clients=true
    echo "Building CLIENTS package"
fi
if [ "$1" == "webui" ]; then
    webui=true
    echo "Building WEBUI package"
fi

/bin/rm setup.py
/bin/cp MANIFEST.in.rucio MANIFEST.in
/bin/cp setup_rucio.py setup.py
# Pre-build one time to ensure correct vcversion file
python setup.py build sdist

if $rucio; then
   /bin/cp MANIFEST.in.rucio MANIFEST.in
   /bin/cp setup_rucio.py setup.py
   # Push on pypi@org
   python setup.py sdist upload
fi

if $clients; then
    /bin/cp MANIFEST.in.client MANIFEST.in
    /bin/cp setup_rucio_client.py setup.py
    # Push on pypi@org
    python setup.py sdist upload
fi

if $webui; then
    /bin/cp MANIFEST.in.webui MANIFEST.in
    /bin/cp setup_webui.py setup.py
    # Push on pypi@org
    python setup.py sdist upload
fi
