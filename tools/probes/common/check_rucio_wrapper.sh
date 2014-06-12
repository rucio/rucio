#!/usr/bin/env sh
# Copyright European Organization for Nuclear Research (CERN) 2013
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013

export RUCIO_HOME="/data/rucio/$2/"
cmd="/data/nagios/rucio/.venv/bin/python /data/nagios/probes/$1"
$cmd
