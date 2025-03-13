# Copyright 2022 CERN
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
# - Mayank Sharma <mayank.sharma@cern.ch>, 2022

FROM docker.io/fedora:35
ARG PYTHON

RUN test "x${PYTHON}" = "x3.10" && \
    dnf update -y && \
    dnf install -y which findutils gridsite libaio memcached httpd mod_ssl python3-pip python3-mod_wsgi python3-gfal2 sqlite gcc \
            python3-devel python-devel python3-wheel python3-kerberos krb5-devel libxml2-devel xmlsec1-devel xmlsec1-openssl-devel \
            libtool-ltdl-devel libnsl nodejs redhat-rpm-config git && \
    alternatives --install /usr/bin/python python /usr/bin/python3.10 1 && \
    alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 1 && \
    python -m pip --no-cache-dir install --upgrade pip && \
    # setuptools will be reinstalled via pip when installing requirements
    dnf remove -y python3-setuptools && \
    dnf clean all && \
    rpm -i https://download.oracle.com/otn_software/linux/instantclient/1912000/oracle-instantclient19.12-basiclite-19.12.0.0.0-1.x86_64.rpm && \
    echo "/usr/lib/oracle/19.12/client64/lib" > /etc/ld.so.conf.d/oracle-instantclient.conf && \
    ldconfig

WORKDIR /usr/local/src/rucio

# pre-install requirements
COPY requirements requirements
RUN python -m pip --no-cache-dir install --upgrade pip && \
    python -m pip --no-cache-dir install --upgrade -r requirements/requirements.server.txt -r requirements/requirements.dev.txt

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
    chmod 0400 etc/certs/ruciouser.key.pem && \
    cp etc/certs/ruciouser.key.pem etc/ruciouser.key.pem

# copy everything else except the git-dir (anything above is cache-friendly)
COPY .pep8 .pycodestyle pyproject.toml setuputil.py setup.py setup_rucio.py setup_rucio_client.py setup_webui.py ./
COPY tools tools
COPY bin bin
COPY lib lib
COPY tests tests

# Install Rucio server + dependencies
RUN python -m pip --no-cache-dir install --upgrade .[oracle,postgresql,mysql,kerberos,dev,saml] && \
    python -m pip list

WORKDIR /opt/rucio
RUN cp -r /usr/local/src/rucio/{lib,bin,tools,etc,tests} ./

CMD ["httpd","-D","FOREGROUND"]
