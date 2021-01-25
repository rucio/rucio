# Copyright 2017-2020 CERN
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
ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8

RUN yum install -y epel-release.noarch && \
    yum -y update && \
    yum install -y gcc httpd gmp-devel krb5-devel mod_ssl mod_auth_kerb git openssl-devel bzip2-devel gridsite which libaio memcached ffi-devel nmap-ncat && \
    yum -y install https://repo.ius.io/ius-release-el7.rpm && \
    yum -y install libxml2-devel xmlsec1-devel xmlsec1-openssl-devel libtool-ltdl-devel python && \
    if [ "$PYTHON" == "2.7" ] ; then yum -y install python-devel python-pip python36u python36u-devel python36u-pip python36u-mod_wsgi ; fi && \
    if [ "$PYTHON" == "3.6" ] ; then yum -y install python36u python36u-devel python36u-pip python36u-mod_wsgi ; fi && \
    yum clean all

WORKDIR /usr/local/src
RUN if [ "$PYTHON" == "2.7" ] ; then ln -sf python2.7 /usr/bin/python && ln -sf pip2.7 /usr/bin/pip ; \
    elif [ "$PYTHON" == "3.6" ] ; then ln -sf python3.6 /usr/bin/python && ln -sf pip3.6 /usr/bin/pip ; \
    elif [ "$PYTHON" == "3.7" ] ; then \
        yum install -y httpd-devel bzip2-devel ncurses-devel sqlite-devel libffi-devel uuid-devel && \
        yum clean all && \
        curl -sSL https://www.python.org/ftp/python/3.7.9/Python-3.7.9.tar.xz | tar xJv && \
        cd Python-3.7.9 && \
        ./configure --enable-optimizations --enable-shared --libdir=/usr/local/lib LDFLAGS="-Wl,-rpath /usr/local/lib" && \
        make -j && \
        make install exec_prefix=/usr && \
        python3.7 -m ensurepip --default-pip && \
        cd .. && rm -rf Python-3.7.9 && \
        ln -sf python3.7 /usr/bin/python && ln -sf python3.7 /usr/bin/python3 && ln -sf pip3.7 /usr/bin/pip && ln -sf pip3.7 /usr/bin/pip3 && \
        cp -al /usr/include/python3.7m/pyconfig.h /usr/local/include/python3.7m/pyconfig.h && \
        cp -al /usr/local/lib/* /usr/lib64/ && \
        curl -sSL https://github.com/GrahamDumpleton/mod_wsgi/archive/4.7.1.tar.gz | tar xzv && \
        cd mod_wsgi-4.7.1 && \
        ./configure --with-python=/usr/bin/python3.7 --prefix=/usr --libdir=/usr/lib64 && \
        make -j && \
        make install && \
        echo -e '# NOTE:\n# Only one mod_wsgi can be loaded at a time.\n# Don'"'"'t attempt to load if already loaded.\n<IfModule !wsgi_module>\n    LoadModule wsgi_module modules/mod_wsgi.so\n</IfModule>\n' > /etc/httpd/conf.modules.d/05-wsgi-python.conf && \
        cd .. && rm -rf mod_wsgi-4.7.1 ; \
    fi

# Install sqlite3 because CentOS ships with an old version without window functions
RUN curl https://www.sqlite.org/2019/sqlite-autoconf-3290000.tar.gz | tar xzv && \
    cd ./sqlite-autoconf-3290000 && \
    ./configure --prefix=/usr/local --libdir=/usr/local/lib64 && \
    make -j && \
    make install && \
    cd .. && rm -rf ./sqlite-autoconf-3290000

RUN if [ "$PYTHON" == "2.7" ] ; then \
        python2 -m pip --no-cache-dir install --upgrade 'pip<21' && \
        python2 -m pip --no-cache-dir install --upgrade setuptools wheel && \
        python3 -m pip --no-cache-dir install --upgrade pip && \
        python3 -m pip --no-cache-dir install --upgrade setuptools wheel && \
        ln -sf python2.7 /usr/bin/python && ln -sf pip2.7 /usr/bin/pip && rm -f /usr/local/bin/pip ; \
    else \
        python -m pip --no-cache-dir install --upgrade pip && \
        python -m pip --no-cache-dir install --upgrade setuptools wheel ; \
    fi

WORKDIR /usr/local/src/rucio

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

RUN rpm -i etc/docker/test/extra/oic.rpm; \
    echo "/usr/lib/oracle/12.2/client64/lib" >/etc/ld.so.conf.d/oracle.conf; \
    ldconfig

# pre-install requirements
RUN if [ "$PYTHON" == "2.7" ] ; then \
        python3 -m pip --no-cache-dir install --upgrade -r etc/pip-requires && \
        python2 -m pip --no-cache-dir install --upgrade -r etc/pip-requires-client -r etc/pip-requires-test ; \
    else \
        python -m pip --no-cache-dir install --upgrade -r etc/pip-requires -r etc/pip-requires-client -r etc/pip-requires-test ; \
    fi

# copy everything else except the git-dir (anything above is cache-friendly)
COPY .flake8 .pep8 .pycodestyle pylintrc setup.py setup_rucio.py setup_rucio_client.py setup_webui.py ./
COPY tools tools
COPY bin bin
COPY doc doc
COPY lib lib

# Install Rucio server + dependencies
RUN if [ "$PYTHON" == "2.7" ] ; then PYEXEC=python3 ; else PYEXEC=python ; fi ; \
    $PYEXEC -m pip --no-cache-dir install --upgrade .[oracle,postgresql,mysql,kerberos,dev,saml]

WORKDIR /opt/rucio
RUN cp -r /usr/local/src/rucio/{lib,bin,tools,etc} ./

CMD ["httpd","-D","FOREGROUND"]
