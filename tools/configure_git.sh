#!/bin/bash
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2015
# Martin Barisits, <martin.barisits@cern.ch>, 2017

git remote add upstream https://github.com/rucio/rucio.git

cp tools/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
cp tools/prepare-commit-msg .git/hooks/prepare-commit-msg
chmod +x .git/hooks/prepare-commit-msg
