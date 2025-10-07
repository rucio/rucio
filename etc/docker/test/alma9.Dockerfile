FROM almalinux:9.1 as base
    WORKDIR /usr/local/src
    ARG PYTHON
    ENV PYTHON $PYTHON
    ENV LANG=en_US.UTF-8
    ENV LC_ALL=en_US.UTF-8
    ENV CPLUS_INCLUDE_PATH="/usr/local/include/python${PYTHON}:/usr/include/python${PYTHON}"
    ENV C_INCLUDE_PATH="/usr/include/python${PYTHON}"
    ENV PYTHON_VENV="/opt/venv"
    ENV PATH="${PYTHON_VENV}/bin:${PATH}"
    ENV PYTHON_310_PATCH_VERSION="4"

FROM base as python
    RUN if [ "$PYTHON" == "3.9" ] ; then \
            dnf install -y epel-release.noarch && \
            dnf install -y 'dnf-command(config-manager)' && \
            dnf config-manager --set-enabled crb && \
            dnf -y update && \
            dnf -y install boost-python3 python3-pip python3-devel && \
            python3 -m pip --no-cache-dir install --upgrade pip && \
            python3 -m pip --no-cache-dir install --upgrade setuptools wheel; \
        elif [ "$PYTHON" == "3.10" ] ; then \
            PYTHON_VERSION="3.10.${PYTHON_310_PATCH_VERSION}" && \
            dnf install -y 'dnf-command(config-manager)' && \
            dnf config-manager --enable crb && \
            dnf -y update && \
            dnf -y install dnf-plugins-core && \
            dnf -y builddep python3 && \
            dnf -y install wget yum-utils make gcc openssl-devel bzip2-devel libffi-devel zlib-devel && \
            wget https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz && \
            tar xzf Python-${PYTHON_VERSION}.tgz && \
            cd Python-${PYTHON_VERSION} && \
            ./configure --enable-optimizations --enable-shared --libdir=/usr/local/lib LDFLAGS="-Wl,-rpath /usr/local/lib" && \
            make -j ${nproc} && \
            make altinstall exec_prefix=/usr && \
            rm -rf Python-${PYTHON_VERSION}.tgz && \
            echo "/usr/local/lib" > /etc/ld.so.conf.d/python${PYTHON}.conf && \
            ldconfig && \
            python${PYTHON} -m pip --no-cache-dir install --upgrade pip && \
            python${PYTHON} -m pip --no-cache-dir install --upgrade setuptools wheel; \
        fi
    RUN python${PYTHON} -m venv ${PYTHON_VENV}

FROM python as gfal2
    RUN dnf install -y epel-release.noarch && \
        dnf install -y 'dnf-command(config-manager)' && \
        dnf config-manager --enable crb && \
        dnf -y update && \
        dnf -y install gfal2-devel && \
        if [ "$PYTHON" == "3.9" ] ; then \
            dnf -y install gfal2-python3 && \
            cp /usr/lib64/python3.9/site-packages/gfal2.so /usr/lib64/gfal2.so; \
        elif [ "$PYTHON" == "3.10" ] ; then \
            wget https://archives.boost.io/release/1.80.0/source/boost_1_80_0.tar.gz && \
            tar -xvzf boost_1_80_0.tar.gz && \
            cd boost_1_80_0 && \
            ./bootstrap.sh --with-libraries=python --with-python=/usr/bin/python3.10 --prefix=/usr/ --libdir=/usr/local/lib && \
            ./b2 --with-python --libdir=/usr/local/lib --link=shared && \
            cp /usr/local/src/boost_1_80_0/stage/lib/lib* /usr/lib64/ && \
            dnf install -y git dnf-plugins-core git rpm-build tree which cmake make gcc gcc-c++ && \
            git clone --depth 1 --branch v1.12.0 https://github.com/cern-fts/gfal2-python.git && \
            cd gfal2-python && \
            cd ./packaging && \
            RPMBUILD_SRC_EXTRA_FLAGS="--without docs --without python2" make srpm && \
            dnf -y builddep gfal2-python-1.12.0-1.el9.src.rpm && \
            cd ../ && \
            CPLUS_INCLUDE_PATH=$CPLUS_INCLUDE_PATH:/usr/local/src/boost_1_80_0  python3 -m pip --no-cache-dir install . && \
            cd .. && rm -rf gfal2-python && \
            dnf remove -y boost-python3 && \
            cp ${PYTHON_VENV}/lib/python${PYTHON}/site-packages/gfal2.so /usr/lib64/gfal2.so; \
        fi

FROM python as mod_wsgi
    RUN if [ "$PYTHON" == "3.9" ] ; then \
            dnf install -y python3-mod_wsgi && \
            cp /usr/lib64/httpd/modules/mod_wsgi_python3.so /usr/lib64/httpd/modules/mod_wsgi.so; \
        elif [ "$PYTHON" == "3.10" ] ; then \
            dnf install -y httpd-devel && \
            curl -sSL https://github.com/GrahamDumpleton/mod_wsgi/archive/4.9.1.tar.gz | tar xzv && \
            cd mod_wsgi-4.9.1 && \
            ./configure --with-python=/usr/bin/python${PYTHON} --prefix=/usr --libdir=/usr/local/lib && \
            make -j && \
            make install; \
        fi && \
        echo -e '# NOTE:\n# Only one mod_wsgi can be loaded at a time.\n# Don'"'"'t attempt to load if already loaded.\n<IfModule !wsgi_module>\n    LoadModule wsgi_module modules/mod_wsgi.so\n</IfModule>\n' > /etc/httpd/conf.modules.d/05-wsgi-python.conf;

FROM python as rucio-runtime
    WORKDIR /usr/local/src/rucio

    RUN dnf install -y epel-release.noarch && \
        dnf install -y 'dnf-command(config-manager)' && \
        dnf config-manager --enable crb && \
        dnf -y update && \
        dnf install -y \
        xmlsec1-devel xmlsec1-openssl-devel pkg-config libtool-ltdl-devel \
        httpd-devel \
        libnsl libaio \
        memcached \
        gridsite \
        sqlite \
        gfal2-devel \
        nodejs npm \
        glibc-langpack-en

    COPY tools tools
    COPY bin bin
    COPY lib lib
    COPY etc etc
    COPY tests tests
    COPY requirements requirements
    COPY .pep8 .pycodestyle pyproject.toml setup.py setup_rucio.py setup_rucio_client.py setup_webui.py setuputil.py ./

    RUN mkdir -p /var/log/rucio/trace && \
        chmod -R 777 /var/log/rucio && \
        mkdir -p /etc/grid-security && \
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

FROM rucio-runtime as requirements
    RUN dnf -y update --nobest && \
        dnf -y --skip-broken install make gcc krb5-devel xmlsec1-devel xmlsec1-openssl-devel pkg-config libtool-ltdl-devel git && \
        python3 -m pip --no-cache-dir install --upgrade pip && \
        python3 -m pip --no-cache-dir install --upgrade setuptools wheel && \
        python3 -m pip --no-cache-dir install --upgrade -r requirements/requirements.server.txt -r requirements/requirements.dev.txt

    COPY .pep8 .pycodestyle pyproject.toml setup.py setup_rucio.py setup_rucio_client.py setup_webui.py ./
    RUN python3 -m pip --no-cache-dir install --upgrade .[oracle,postgresql,mysql,kerberos,saml,dev] && \
        python3 -m pip list

FROM rucio-runtime as final

    COPY --from=gfal2 /usr/include/gfal2 /usr/include/gfal2
    COPY --from=gfal2 /usr/lib64/* /usr/lib64/
    COPY --from=gfal2 /usr/lib64/libboost_python3* /usr/lib64/
    COPY --from=gfal2 /usr/lib64/gfal2.so /usr/lib64/gfal2.so

    RUN mv /usr/lib64/gfal2.so ${PYTHON_VENV}/lib/python${PYTHON}/site-packages/gfal2.so;

    COPY --from=requirements ${PYTHON_VENV} ${PYTHON_VENV}
    COPY --from=mod_wsgi /usr/lib64/httpd/modules /usr/lib64/httpd/modules
    COPY --from=mod_wsgi /etc/httpd/conf.modules.d/05-wsgi-python.conf  /etc/httpd/conf.modules.d/05-wsgi-python.conf

    WORKDIR /opt/rucio
    RUN cp -r /usr/local/src/rucio/{lib,bin,tools,etc,tests} ./

    RUN ldconfig

    CMD ["httpd","-D","FOREGROUND"]
