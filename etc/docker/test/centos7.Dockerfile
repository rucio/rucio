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
    if [ "$PYTHON" == "3.6" ] ; then yum -y install python36u python36u-devel python36u-pip python36u-mod_wsgi gfal2-python3 ; fi && \
    if [ "$PYTHON" == "3.7" ] ; then yum -y install httpd-devel ncurses-devel sqlite-devel libffi-devel uuid-devel rpm-build rpmdevtools redhat-rpm-config boost-devel \
            gcc-c++ libicu-devel libstdc++-devel m4 mpich-devel openmpi-devel python2-devel zlib-devel chrpath docbook-dtds docbook-style-xsl cmake glib2-devel gfal2-devel ; fi && \
    yum clean all

WORKDIR /usr/local/src

RUN if [ "$PYTHON" == "3.6" ] ; then \
        python3.6 -m pip --no-cache-dir install --upgrade pip && \
        python3.6 -m pip --no-cache-dir install --upgrade setuptools wheel && \
        rm -f /usr/bin/python && \
        ln -sf python3.6 /usr/bin/python && \
        ln -sf pip3.6 /usr/bin/pip ; \
    elif [ "$PYTHON" == "3.7" ] ; then \
        curl -sSL https://www.python.org/ftp/python/3.7.9/Python-3.7.9.tar.xz | tar xJv && \
        cd Python-3.7.9 && \
        ./configure --enable-optimizations --enable-shared --libdir=/usr/local/lib LDFLAGS="-Wl,-rpath /usr/local/lib" && \
        make -j && \
        make install exec_prefix=/usr && \
        python3.7 -m ensurepip --default-pip && \
        cd .. && rm -rf Python-3.7.9 && \
        cp -al /usr/include/python3.7m/pyconfig.h /usr/local/include/python3.7m/pyconfig.h && \
        rm -rf /usr/include/python3.7m/ && \
        ln -sf ../local/include/python3.7m /usr/include/python3.7m && \
        cp -al /usr/local/lib/* /usr/lib64/ && \
        python3.7 -m pip --no-cache-dir install --upgrade pip && \
        python3.7 -m pip --no-cache-dir install --upgrade setuptools wheel && \
        useradd mockbuild && \
        groupadd mock && \
        usermod -G mock -a mockbuild && \
        rpmdev-setuptree && \
        echo -e '\n%_buildshell /bin/bash\n%python3_pkgversion 37\n' >> ~/.rpmmacros && \
        curl -sSL https://download-ib01.fedoraproject.org/pub/epel/7/source/tree/Packages/b/boost-python3-1.53.0-30.el7.src.rpm > boost-python3-1.53.0-30.el7.src.rpm && \
        rpm -i boost-python3-1.53.0-30.el7.src.rpm && \
        rm -f boost159-1.59.0-3.el7ost.src.rpm && \
        curl -sSL https://github.com/boostorg/python/commit/660487c43fde76f3e64f1cb2e644500da92fe582.patch > ~/rpmbuild/SOURCES/boost-python37.patch && \
        sed 's;/src/;/libs/python/src/;g' -i ~/rpmbuild/SOURCES/boost-python37.patch && \
        sed 's;#Patch70: boost-1.53-spirit-lexer.patch;#Patch70: boost-1.53-spirit-lexer.patch\n\n# Fix build with Python 3.7\nPatch71: boost-python37.patch;' -i ~/rpmbuild/SPECS/boost-python3.spec && \
        sed 's;#%patch70 -p2;#%patch70 -p2\n%patch71 -p1;' -i ~/rpmbuild/SPECS/boost-python3.spec && \
        sed 's;BuildRequires: python%{python3_pkgversion}-devel;;' -i ~/rpmbuild/SPECS/boost-python3.spec && \
        sed 's;%ldconfig_scriptlets;;' -i ~/rpmbuild/SPECS/boost-python3.spec && \
        QA_RPATHS=$[ 0x0001|0x0002 ] rpmbuild -ba ~/rpmbuild/SPECS/boost-python3.spec && \
        rpm -i --nodeps ~/rpmbuild/RPMS/**/* && \
        rm -rf ~/rpmbuild && \
        curl -sSL https://github.com/cern-fts/gfal2-python/archive/refs/tags/v1.9.5.tar.gz | tar xzv && \
        cd gfal2-python-1.9.5/ && \
        curl -sSL https://github.com/cern-fts/gfal2-python/raw/v1.10.1/cmake/modules/FindPythonEasy.cmake > cmake/modules/FindPythonEasy.cmake && \
        sed 's;find_package(PythonEasy REQUIRED);find_package(PythonEasy REQUIRED)\nset(PYTHON_LIBRARIES_3 "/usr/local/lib/python3.7/")\nset(PYTHON_SITE_PACKAGES_3 "/usr/local/lib/python3.7/site-packages/")\nset(PYTHON_INCLUDE_PATH_3 "/usr/include/python3.7m/")\nset(PYTHON_EXECUTABLE_3 "/usr/bin/python3.7");' -i CMakeLists.txt && \
        sed 's;# Python 2;# Python 2 (OFF)\nif (OFF);' -i src/CMakeLists.txt && \
        sed 's;# If available, Python3;endif ()\n\n# Python 3;' -i src/CMakeLists.txt && \
        python3.7 -m pip --no-cache-dir install . && \
        cd .. && rm -rf gfal2-python-1.9.5 && \
        curl -sSL https://github.com/GrahamDumpleton/mod_wsgi/archive/4.7.1.tar.gz | tar xzv && \
        cd mod_wsgi-4.7.1 && \
        ./configure --with-python=/usr/bin/python3.7 --prefix=/usr --libdir=/usr/local/lib && \
        make -j && \
        make install && \
        echo -e '# NOTE:\n# Only one mod_wsgi can be loaded at a time.\n# Don'"'"'t attempt to load if already loaded.\n<IfModule !wsgi_module>\n    LoadModule wsgi_module modules/mod_wsgi.so\n</IfModule>\n' > /etc/httpd/conf.modules.d/05-wsgi-python.conf && \
        cd .. && rm -rf mod_wsgi-4.7.1 && \
        rm -f /usr/bin/python && \
        ln -sf python3.7 /usr/bin/python && \
        ln -sf python3.7 /usr/bin/python3 && \
        ln -sf pip3.7 /usr/bin/pip && \
        ln -sf pip3.7 /usr/bin/pip3 ; \
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
