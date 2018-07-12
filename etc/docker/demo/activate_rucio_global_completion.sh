#!/usr/bin/env sh
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#                       http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013

# Script to enable shell completion on the rucio commands

eval "$(register-python-argcomplete rucio)"
eval "$(register-python-argcomplete rucio-admin)"
