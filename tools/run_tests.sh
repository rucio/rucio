
#!/bin/bash
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

# Cleanup *pyc
echo "cleaning *.pyc files"
find lib -iname *.pyc | xargs rm

# Cleanup old token
rm -rf /tmp/.rucio_*/

 ./tools/reset_database.py 

# Run nosetests
nosetests -v --logging-filter=-sqlalchemy,-migrate,-requests,-rucio.client.baseclient
nosetests -v --logging-filter=-sqlalchemy,-migrate,-requests,-rucio.client.baseclient
