# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

creds = {'username': 'ddmlab', 'password': 'secret'}

from rucio.client import Client

c = Client(host='localhost', port=443, account='root', ca_cert='/opt/rucio/etc/web/ca.crt', auth_type='userpass', creds=creds)

print c.ping()
