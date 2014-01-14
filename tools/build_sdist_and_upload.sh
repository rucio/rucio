#!/bin/bash
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# Vincent Garonne, <vincent.garonne@cern.ch>, 2012

/bin/cp setup_rucio.py setup.py
python setup.py --release register -r http://atlas-pip.cern.ch/ sdist upload -r http://atlas-pip.cern.ch/
/bin/cp setup_rucio_client.py setup.py
python setup.py --release register -r http://atlas-pip.cern.ch/ sdist upload -r http://atlas-pip.cern.ch/
/bin/cp setup_rucio.py setup.py
