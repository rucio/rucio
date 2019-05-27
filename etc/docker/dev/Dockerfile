# Copyright 2017-2019 CERN for the benefit of the ATLAS collaboration.
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
# - Vincent Garonne <vgaronne@gmail.com>, 2017-2019
# - Cedric Serfon <cedric.serfon@cern.ch>, 2017
# - Frank Berghaus <frank.berghaus@cern.ch>, 2017-2018

FROM centos:7

ADD etc/docker/dev/ca.repo /etc/yum.repos.d/ca.repo

RUN yum -y update && yum clean all && yum install -y epel-release &&\
    yum install -y \
      gcc \
      httpd \
      mod_ssl \
      mod_auth_kerb \
      mod_wsgi \
      python \
      python-pip \
      python-devel \
      python34 \
      python34-pip \
      python34-devel \
      gmp-devel \
      krb5-devel \
      git \
      openssl-devel \
      gridsite \
      which \
      libaio \
      mysql-devel \
      memcached

ENV RUCIOHOME=/opt/rucio
RUN mkdir -p $RUCIOHOME
WORKDIR $RUCIOHOME
RUN mkdir -p \
      bin \
      etc \
      lib/rucio \
      tools

COPY .pep8 .pep8
COPY .flake8 .flake8
COPY pylintrc /etc/pylintrc
COPY etc etc
COPY tools tools

RUN pip install --upgrade pip && pip install --upgrade setuptools
RUN rm -rf /usr/lib/python2.7/site-packages/ipaddress*
RUN pip install -r tools/pip-requires-client
RUN pip install -r tools/pip-requires
RUN pip install -r tools/pip-requires-test
RUN pip install mysql
RUN ln -s $RUCIOHOME/lib/rucio /usr/lib/python2.7/site-packages/rucio
RUN ln -s $RUCIOHOME/lib/rucio /usr/lib/python3.4/site-packages/rucio

RUN mkdir /var/log/rucio /var/log/rucio/trace && chmod 777 /var/log/rucio

COPY etc/docker/dev/rucio.cfg  $RUCIOHOME/etc/rucio.cfg
COPY etc/docker/dev/alembic_mysql.ini  $RUCIOHOME/etc/alembic.ini
COPY etc/docker/dev/aliases-py27.conf $RUCIOHOME/etc/web/aliases-py27.conf
COPY etc/docker/dev/ui-aliases-py27.conf $RUCIOHOME/etc/web/ui-aliases-py27.conf
COPY etc/docker/travis/google-cloud-storage-test.json $RUCIOHOME/etc/google-cloud-storage-test.json
COPY etc/docker/dev/certs/ca.pem $RUCIOHOME/etc/web/CERN-bundle.pem
COPY etc/docker/dev/certs/ca.pem $RUCIOHOME/etc/web/ca.crt

COPY etc/docker/dev/httpd.conf /etc/httpd/conf/httpd.conf
COPY etc/docker/dev/rucio.conf /etc/httpd/conf.d/rucio.conf
COPY etc/docker/dev/certs/usercert.pem $RUCIOHOME/etc/web/usercert.pem
COPY etc/docker/dev/certs/server.crt /etc/grid-security/hostcert.pem
COPY etc/docker/dev/certs/server.key /etc/grid-security/hostkey.pem

RUN chmod 400 /etc/grid-security/hostkey.pem &&\
    rm -rf $RUCIOHOME/tools && mkdir -p $RUCIOHOME/tools &&\
    mkdir -p /etc/httpd &&\
    echo "" > /etc/httpd/conf.d/ssl.conf &&\
    echo "" > /etc/httpd/conf.d/autoindex.conf &&\
    echo "" > /etc/httpd/conf.d/userdir.conf &&\
    echo "" > /etc/httpd/conf.d/welcome.conf &&\
    echo "" > /etc/httpd/conf.d/ssl.conf &&\
    echo "" > /etc/httpd/conf.d/autoindex.conf &&\
    echo "" > /etc/httpd/conf.d/userdir.conf &&\
    echo "" > /etc/httpd/conf.d/welcome.conf

EXPOSE 443

ENV PATH $PATH:$RUCIOHOME/bin

CMD ["httpd","-D","FOREGROUND"]
