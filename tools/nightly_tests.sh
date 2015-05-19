#!/bin/bash
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2015

# tmp directory reset
rm -rf /tmp/rucio_build
mkdir -p /tmp/rucio_build
cd /tmp/rucio_build

# Get the master
export GIT_SSL_NO_VERIFY=1
git clone https://rucio-gerrit.cern.ch/p/rucio

# Install the Rucio virtual env
cd rucio/
python ./tools/install_venv.py

# restart http
/sbin/service httpd restart

# restart memcached
/sbin/service memcached restart

# Run the test-suite
output_file=rucio_tests_`date +"%m_%d_%Y"`
./tools/run_tests.sh > $output_file 2>&1

# mail the output to rucio-dev
# { echo -e "$Message_Success\n\n" ; cat  $output_file ; } | mail -s "Test-Suite" "$Recipients"