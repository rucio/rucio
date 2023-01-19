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
ACCOUNT=anton
IDENTITY=antonid
EMAIL='antonmail@mail.ch'
PASSWORD=anton
SCOPE=user.anton
DATASET=antondset
RSE=XRD1

rucio-admin account add $ACCOUNT
rucio-admin account add-attribute --key 'admin' --value true $ACCOUNT

# add userpass identity
rucio-admin identity add --account $ACCOUNT --type USERPASS --id $IDENTITY --email $EMAIL --pass $PASSWORD

# ( logging into rucio UI requires you to use the IDENTITY not the ACCOUNT)

# create scope antonscope
rucio-admin scope add --account $ACCOUNT --scope $SCOPE
rucio-admin scope add --account $ACCOUNT --scope user.$ACCOUNT
# test using rucio list-scopes

# add dataset antondset
rucio add-dataset $SCOPE:$DATASET

# create test files numbered tfile1.txt through tfile3.txt
echo 'Creating test files'
echo {1..3} | sed -e 's/\s/\n/g' | xargs -I{} sh -c "echo hello test no {} >> tfile{}.txt"

rucio upload --scope $SCOPE --rse $RSE tfile*

rucio-admin account set-limits $ACCOUNT $RSE infinity

rucio attach $SCOPE:$DATASET $SCOPE:tfile{1..3}.txt

rucio add-rule $SCOPE:$DATASET 1 $RSE
