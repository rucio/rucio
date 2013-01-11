#!/usr/bin/env sh
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

scp  ddmusr01@voatlas73:/data/ddmusr01/x509up .
chmod 600 x509up 
export X509_USER_PROXY=`pwd`/x509up
