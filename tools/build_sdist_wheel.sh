#!/bin/bash
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

/bin/rm pyproject.toml
/bin/cp MANIFEST.server.in MANIFEST.in
/bin/cp pyproject.server.toml pyproject.toml
# Pre-build one time to ensure correct vcversion file
python3 -m build --sdist

if $rucio; then
   /bin/cp MANIFEST.server.in MANIFEST.in
   /bin/cp pyproject.server.toml pyproject.toml
   # Push on pypi@org
   python3 -m build
fi

if $clients; then
   /bin/cp MANIFEST.client.in MANIFEST.in
   /bin/cp pyproject.client.toml pyproject.toml
    # Push on pypi@org
    python3 -m build
fi

if $webui; then
   /bin/cp MANIFEST.webui.in MANIFEST.in
   /bin/cp pyproject.webui.toml pyproject.toml
    # Push on pypi@org
    python3 -m build
fi
