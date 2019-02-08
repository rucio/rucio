# Copyright 2017-2018 CERN for the benefit of the ATLAS collaboration.
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
#
# Authors:
# - Thomas Beermann <thomas.beermann@cern.ch>, 2017-2019
# - Vincent Garonne <vgaronne@gmail.com>, 2017-2018
# - Martin Barisits <martin.barisits@cern.ch>, 2017
# - Frank Berghaus <frank.berghaus@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019

FROM centos:7

WORKDIR /tmp
ADD oic.rpm /tmp

RUN yum -y update
RUN yum clean all

RUN yum install -y epel-release.noarch

RUN yum install -y gcc
RUN yum install -y httpd
RUN yum install -y python-pip gmp-devel krb5-devel httpd mod_ssl mod_auth_kerb mod_wsgi git python-devel.x86_64 openssl-devel.x86_64 gridsite which MySQL-python libaio memcached
RUN yum install -y python34 python34-pip python34-devel
RUN rm -rf /usr/lib/python2.7/site-packages/ipaddress*

WORKDIR /opt

RUN mkdir /opt/rucio

COPY . /opt/rucio/
COPY changed_files.txt /opt/rucio/

WORKDIR /opt/rucio

RUN rpm -i /tmp/oic.rpm; \
    echo "/usr/lib/oracle/12.2/client64/lib" >/etc/ld.so.conf.d/oracle.conf; \
    ldconfig

RUN pip install --upgrade pip

# Get the latest setuptools version
# to fix the setup.py error:
# install fails with: `install_requires` must be a string or list of strings
RUN pip install --upgrade setuptools

# Install Rucio + dependencies
RUN pip install .[oracle,postgresql,mysql,kerberos,dev]

RUN cp etc/docker/travis/aliases-py27.conf etc/web/aliases-py27.conf
RUN cp etc/docker/travis/google-cloud-storage-test.json etc/google-cloud-storage-test.json

RUN mkdir /var/log/rucio
RUN mkdir /var/log/rucio/trace
RUN chmod 777 /var/log/rucio

RUN cp etc/docker/travis/httpd.conf /etc/httpd/conf/httpd.conf
RUN cp etc/docker/travis/rucio.conf /etc/httpd/conf.d/rucio.conf

RUN cp etc/docker/travis/certs/ca.pem /opt/rucio/etc/web/CERN-bundle.pem
RUN cp etc/docker/travis/certs/ca.pem /opt/rucio/etc/web/ca.crt
RUN cp etc/docker/travis/certs/usercert.pem /opt/rucio/etc/web/usercert.pem

RUN cp etc/docker/travis/certs/server.crt /etc/grid-security/hostcert.pem
RUN cp etc/docker/travis/certs/server.key /etc/grid-security/hostkey.pem
RUN chmod 400 /etc/grid-security/hostkey.pem

RUN rm /etc/httpd/conf.d/ssl.conf /etc/httpd/conf.d/autoindex.conf /etc/httpd/conf.d/userdir.conf /etc/httpd/conf.d/welcome.conf

CMD ["httpd","-D","FOREGROUND"]
