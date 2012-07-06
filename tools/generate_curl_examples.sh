#!/bin/bash
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# Vincent Garonne, <vincent.garonne@cern.ch>, 2012

# Generate curl example outputs

# Service
doc/source/curl_examples/get_api.sh  > doc/source/curl_examples/get_api.sh   2>&1

# Authentication
doc/source/curl_examples/get_auth_userpass.sh  > doc/source/curl_examples/get_auth_userpass.out   2>&1
doc/source/curl_examples/get_auth_x509.sh  > doc/source/curl_examples/get_auth_x509.out   2>&1
doc/source/curl_examples/get_auth_gss.sh  > doc/source/curl_examples/get_auth_gss.out   2>&1

doc/source/curl_examples/get_auth_validate.sh  > doc/source/curl_examples/get_auth_validate.out 2>&1

# Accounts
doc/source/curl_examples/post_account.sh > doc/source/curl_examples/post_account.out 2>&1
doc/source/curl_examples/put_account.sh  > doc/source/curl_examples/put_account.out 2>&1
doc/source/curl_examples/get_account.sh  > doc/source/curl_examples/get_account.out 2>&1
doc/source/curl_examples/get_account_whoami.sh > doc/source/curl_examples/get_account_whoami.out 2>&1
doc/source/curl_examples/get_accounts.sh > doc/source/curl_examples/get_accounts.out 2>&1
doc/source/curl_examples/del_account.sh > doc/source/curl_examples/del_account.out 2>&1

# Locations
doc/source/curl_examples/post_location.sh  > doc/source/curl_examples/post_location.out 2>&1
doc/source/curl_examples/get_location.sh  > doc/source/curl_examples/get_location.out 2>&1
doc/source/curl_examples/get_locations.sh  > doc/source/curl_examples/get_locations.out 2>&1
doc/source/curl_examples/del_location.sh > doc/source/curl_examples/del_location.out 2>&1

# RSEs
doc/source/curl_examples/post_location_rse.sh  > doc/source/curl_examples/post_location_rse.out 2>&1


# Scope
doc/source/curl_examples/put_scope.sh > doc/source/curl_examples/put_scope.out 2>&1
doc/source/curl_examples/get_scopes.sh > doc/source/curl_examples/get_scopes.out 2>&1
