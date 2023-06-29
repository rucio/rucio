# Copyright 2020-2021 CERN
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
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Mario Lassnig <mario.lassnig@cern.ch>, 2020
# - Martin Barisits <martin.barisits@cern.ch>, 2020-2021

FROM centos:7
ARG PYTHON
ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8

RUN yum install -y epel-release.noarch && \
    yum -y update && \
    yum -y install gcc httpd gmp-devel krb5-devel mod_ssl mod_auth_kerb git openssl-devel bzip2-devel gridsite which libaio memcached ffi-devel nmap-ncat nodejs npm && \
    yum -y install https://repo.ius.io/ius-release-el7.rpm && \
    yum -y install libxml2-devel xmlsec1-devel xmlsec1-openssl-devel libtool-ltdl-devel python && \
    yum -y install python36u python36u-devel python36u-pip python36u-mod_wsgi gfal2-python3 && \
    yum clean all

WORKDIR /usr/local/src

RUN if [ "$PYTHON" == "3.6" ] ; then \
        python3.6 -m pip --no-cache-dir install --upgrade pip && \
        python3.6 -m pip --no-cache-dir install --upgrade setuptools wheel && \
        rm -f /usr/bin/python && \
        ln -sf python3.6 /usr/bin/python && \
        ln -sf pip3.6 /usr/bin/pip ; \
    fi

# Install sqlite3 because CentOS ships with an old version without window functions
RUN curl https://www.sqlite.org/2019/sqlite-autoconf-3290000.tar.gz | tar xzv && \
    cd ./sqlite-autoconf-3290000 && \
    ./configure --prefix=/usr/local --libdir=/usr/local/lib64 && \
    make -j && \
    make install && \
    cd .. && rm -rf ./sqlite-autoconf-3290000

WORKDIR /usr/local/src/rucio

COPY requirements.txt setuputil.py ./

# pre-install requirements
RUN python -m pip --no-cache-dir install --upgrade -r requirements.txt

COPY etc etc

RUN mkdir -p /var/log/rucio/trace && \
    chmod -R 777 /var/log/rucio && \
    cp etc/certs/hostcert_rucio.pem /etc/grid-security/hostcert.pem && \
    cp etc/certs/hostcert_rucio.key.pem /etc/grid-security/hostkey.pem && chmod 0400 /etc/grid-security/hostkey.pem && \
    cp etc/docker/test/extra/httpd.conf /etc/httpd/conf/httpd.conf && \
    cp etc/docker/test/extra/rucio.conf /etc/httpd/conf.d/rucio.conf && \
    cp etc/docker/test/extra/00-mpm.conf /etc/httpd/conf.modules.d/00-mpm.conf && \
    rm /etc/httpd/conf.d/ssl.conf /etc/httpd/conf.d/autoindex.conf /etc/httpd/conf.d/userdir.conf /etc/httpd/conf.d/welcome.conf /etc/httpd/conf.d/zgridsite.conf && \
    cp etc/certs/rucio_ca.pem etc/rucio_ca.pem && \
    cp etc/certs/ruciouser.pem etc/ruciouser.pem && \
    cp etc/certs/ruciouser.key.pem etc/ruciouser.key.pem && \
    chmod 0400 etc/ruciouser.key.pem

RUN rpm -i https://download.oracle.com/otn_software/linux/instantclient/1912000/oracle-instantclient19.12-basiclite-19.12.0.0.0-1.x86_64.rpm && \
    echo "/usr/lib/oracle/19.12/client64/lib" > /etc/ld.so.conf.d/oracle-instantclient.conf && \
    ldconfig

# copy everything else except the git-dir (anything above is cache-friendly)
COPY .flake8 .pep8 .pycodestyle pylintrc setup.py setup_rucio.py setup_rucio_client.py setup_webui.py ./
COPY tools tools
COPY bin bin
COPY lib lib

# Install Rucio server + dependencies
RUN PYEXEC=python ; \
    $PYEXEC -m pip --no-cache-dir install --upgrade .[oracle,postgresql,mysql,kerberos,saml,dev] && \
    $PYEXEC -m pip list

WORKDIR /opt/rucio
RUN cp -r /usr/local/src/rucio/{lib,bin,tools,etc} ./

CMD ["httpd","-D","FOREGROUND"]
