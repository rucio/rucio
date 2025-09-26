#!/bin/bash
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

# wait for MySQL readiness
/usr/local/bin/wait-for-it.sh -h ftsdb -p 3306 -t 3600

# initialise / upgrade the database
/usr/share/fts/fts-database-upgrade.py -y

# Configure the OIDC provider and the mapping and the mapping between the OIDC client id to the VO
# Note: 6fe2a9f5e8876772 is the "automatically generated" vo for the rucios test certificate. It will change if we re-generate the cert.
echo \
 "insert into t_token_provider (name,issuer,client_id,client_secret) values('indigoiam', 'https://indigoiam/', 'd6dad80f-11f7-4cf4-a4ef-fbd081ec7f98', 'AJWL5JZtM6I2iaj7XHYq98kPGo6-8Wde2ScSHJhHNvCLeKppTj9fBmeq2xGWi3RCFlj6cPJFjz-BxXIBva4kDYo');" \
 "insert into t_gridmap (dn,vo) values ('85e6f7a5-580b-4a1c-a6d2-39055143063d', '6fe2a9f5e8876772');" \
 | mysql -h ftsdb -u fts --password=fts fts

# fix Apache configuration
/usr/bin/sed -i 's/Listen 80/#Listen 80/g' /etc/httpd/conf/httpd.conf
cp /opt/rh/httpd24/root/usr/lib64/httpd/modules/mod_rh-python36-wsgi.so /lib64/httpd/modules
cp /opt/rh/httpd24/root/etc/httpd/conf.modules.d/10-rh-python36-wsgi.conf /etc/httpd/conf.modules.d

# Regenerate CA bundle in case new CAs where mounted into /etc/pki/ca-trust/source/anchors/
update-ca-trust

# startup the FTS services
/usr/sbin/fts_server               # main FTS server daemonizes
/usr/sbin/fts_qos                  # for the stager tests
/usr/sbin/fts_activemq             # daemon to send messages to activemq
/usr/sbin/httpd -DFOREGROUND       # FTS REST frontend & FTSMON
