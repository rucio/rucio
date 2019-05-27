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

RUN yum -y update
RUN yum clean all

RUN yum install -y epel-release.noarch

RUN yum install -y gcc
RUN yum install -y httpd
RUN yum install -y python-pip gmp-devel krb5-devel httpd mod_ssl mod_auth_kerb mod_wsgi git python-devel.x86_64 openssl-devel.x86_64 gridsite which MySQL-python libaio memcached
RUN yum -y install https://centos7.iuscommunity.org/ius-release.rpm
RUN yum -y install python36u python36u-devel python36u-pip python35u python35u-devel python35u-pip
RUN rm -rf /usr/lib/python2.7/site-packages/ipaddress*

# Install sqlite3 version 3.28
RUN curl https://www.sqlite.org/2019/sqlite-autoconf-3280000.tar.gz > sqlite.tar.gz
RUN tar xvfz sqlite.tar.gz
WORKDIR ./sqlite-autoconf-3280000
RUN ./configure --prefix=/usr/local
RUN make
RUN make install
WORKDIR /usr/local
RUN mv lib/libsqlite3.so /lib64
RUN mv lib/libsqlite3.so.0 /lib64
RUN mv lib/libsqlite3.so.0.8.6 /lib64

WORKDIR /opt

RUN mkdir /opt/rucio

COPY . /opt/rucio/
COPY changed_files.txt /opt/rucio/

WORKDIR /opt/rucio

RUN rpm -i /opt/rucio/etc/docker/travis/oic.rpm; \
    echo "/usr/lib/oracle/12.2/client64/lib" >/etc/ld.so.conf.d/oracle.conf; \
    ldconfig

ARG python

RUN if [ "$python" == "3.6" ] ; then rm -r /usr/bin/python -f & ln -s /usr/bin/python3.6 /usr/bin/python ; elif [ "$python" == "3.5" ] ; then rm -r /usr/bin/python -f & ln -s /usr/bin/python3.5 /usr/bin/python ; fi
RUN if [ "$python" == "3.6" ] ; then echo "alias python=python3.6" >> ~/.bashrc ; elif [ "$python" == "3.5" ] ; then echo "alias python=python3.5" >> ~/.bashrc ; fi

RUN if [ "$python" == "3.6" ] ; then pip3.6 install --upgrade pip ; elif [ "$python" == "3.5" ] ; then pip3.5 install --upgrade pip ; else pip install --upgrade pip ; fi

# Get the latest setuptools version
# to fix the setup.py error:
# install fails with: `install_requires` must be a string or list of strings
RUN if [ "$python" == "3.6" ] ; then pip3.6 install --upgrade setuptools ; elif [ "$python" == "3.5" ] ; then pip3.5 install --upgrade setuptools ; else pip install --upgrade setuptools ; fi

# Install Rucio + dependencies
RUN if [ "$python" == "3.6" ] ; then pip3.6 install .[oracle,postgresql,mysql,kerberos,dev] ; elif [ "$python" == "3.5" ] ; then pip3.5 install .[oracle,postgresql,mysql,kerberos,dev] ; else pip install .[oracle,postgresql,mysql,kerberos,dev] ; fi

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
