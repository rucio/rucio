# Copyright 2017-2020 CERN for the benefit of the ATLAS collaboration.
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019
# - Ruturaj Gujar <ruturaj.gujar23@gmail.com>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

FROM centos:7
ARG PYTHON

RUN yum install -y epel-release.noarch && \
  yum -y update && \
  yum install -y gcc httpd python-pip gmp-devel krb5-devel httpd mod_ssl mod_auth_kerb git python-devel.x86_64 openssl-devel.x86_64 gridsite which libaio memcached MySQL-python ffi-devel nmap-ncat && \
  yum -y install https://repo.ius.io/ius-release-el7.rpm && \
  if [ "$PYTHON" == "3.6" ] ; then yum -y install python36u python36u-devel python36u-pip ; fi && \
  yum -y install libxml2-devel xmlsec1-devel xmlsec1-openssl-devel libtool-ltdl-devel && \
  if [ "$PYTHON" == "3.6" ] ; then yum -y install python36u-mod_wsgi ; else yum -y install mod_wsgi ; fi && \
  yum clean all

RUN rm -rf /usr/lib/python2.7/site-packages/ipaddress*

# Install sqlite3 because CentOS ships with an old version without window functions
RUN curl https://www.sqlite.org/2019/sqlite-autoconf-3290000.tar.gz | tar xzv && \
  cd ./sqlite-autoconf-3290000 && \
  ./configure --prefix=/usr/local --libdir=/usr/local/lib64 && \
  make -j && \
  make install && \
  cd .. && rm -rf ./sqlite-autoconf-3290000

RUN if [ "$PYTHON" == "2.7" ] ; then ln -sf python2.7 /usr/bin/python ; ln -sf pip2.7 /usr/bin/pip ; fi
RUN if [ "$PYTHON" == "3.6" ] ; then ln -sf python3.6 /usr/bin/python ; ln -sf pip3.6 /usr/bin/pip ; fi
# Get the latest setuptools version
# to fix the setup.py error:
# install fails with: `install_requires` must be a string or list of strings
RUN if [ "$PYTHON" == "2.7" ] ; then pip install --no-cache-dir --upgrade pip 'setuptools<45' ; \
    else pip install --no-cache-dir --upgrade pip setuptools ; fi && \
    pip install --no-cache-dir -U wheel

RUN mkdir -p /var/log/rucio/trace && \
  chmod -R 777 /var/log/rucio

WORKDIR /usr/local/src/rucio

COPY etc etc

RUN cp etc/certs/hostcert_rucio.pem /etc/grid-security/hostcert.pem && \
  cp etc/certs/hostcert_rucio.key.pem /etc/grid-security/hostkey.pem && chmod 0400 /etc/grid-security/hostkey.pem && \
  cp etc/docker/test/extra/httpd.conf /etc/httpd/conf/httpd.conf && \
  cp etc/docker/test/extra/rucio.conf /etc/httpd/conf.d/rucio.conf && \
  cp etc/docker/test/extra/00-mpm.conf /etc/httpd/conf.modules.d/00-mpm.conf && \
  rm /etc/httpd/conf.d/ssl.conf /etc/httpd/conf.d/autoindex.conf /etc/httpd/conf.d/userdir.conf /etc/httpd/conf.d/welcome.conf /etc/httpd/conf.d/zgridsite.conf && \
  cp etc/certs/rucio_ca.pem etc/rucio_ca.pem && \
  cp etc/certs/ruciouser.pem etc/ruciouser.pem && \
  cp etc/certs/ruciouser.key.pem etc/ruciouser.key.pem

RUN rpm -i etc/docker/test/extra/oic.rpm; \
    echo "/usr/lib/oracle/12.2/client64/lib" >/etc/ld.so.conf.d/oracle.conf; \
    ldconfig

# pre-install requirements
RUN pip install --no-cache-dir -r etc/pip-requires -r etc/pip-requires-client -r etc/pip-requires-test \
    'cx_oracle==6.3.1' 'psycopg2-binary>=2.4.2,<2.8' 'PyMySQL' 'kerberos>=1.3.0' 'pykerberos>=1.2.1' 'requests-kerberos>=0.12.0' 'python3-saml>=1.6.0'

# copy everything else (anything above is cache-friendly)
COPY . .

# Install Rucio + dependencies
RUN pip install --no-cache-dir .[oracle,postgresql,mysql,kerberos,dev,saml]

WORKDIR /opt/rucio
RUN cp -r /usr/local/src/rucio/{lib,bin,tools,etc} ./

CMD ["httpd","-D","FOREGROUND"]
