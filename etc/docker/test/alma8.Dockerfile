FROM almalinux:8.7 as base
    WORKDIR /usr/local/src
    ARG PYTHON
    ENV PYTHON $PYTHON
    ENV LANG=en_US.UTF-8
    ENV LC_ALL=en_US.UTF-8
    ENV CPLUS_INCLUDE_PATH="/usr/include/python${PYTHON}"
    ENV C_INCLUDE_PATH="/usr/include/python${PYTHON}"
    ENV PYTHON_VENV="/opt/venv"
    ENV PATH="${PYTHON_VENV}/bin:${PATH}"
    ENV PYTHON_37_PATCH_VERSION="9"
    ENV PYTHON_38_PATCH_VERSION="12"
    ENV PYTHON_39_PATCH_VERSION="13"
    ENV PYTHON_310_PATCH_VERSION="4"
    RUN dnf update -y && \
        dnf install -y 'dnf-command(config-manager)'

FROM base as oracle-client
    RUN dnf install -y libnsl libaio
    RUN rpm -i https://download.oracle.com/otn_software/linux/instantclient/1912000/oracle-instantclient19.12-basiclite-19.12.0.0.0-1.x86_64.rpm && \
        echo "/usr/lib/oracle/19.12/client64/lib" > /etc/ld.so.conf.d/oracle-instantclient.conf;

FROM base as python
    RUN if [ "$PYTHON" == "3.6" ] ; then \
            dnf install -y epel-release.noarch && \
            dnf config-manager --enable powertools && \
            dnf -y update && \
            dnf -y install python3 boost-python3 python3-pip python3-devel && \
            python3.6 -m pip --no-cache-dir install --upgrade pip && \
            python3.6 -m pip --no-cache-dir install --upgrade setuptools wheel; \
        elif [[ "$PYTHON" == "3.7" || "$PYTHON" == "3.8" || "$PYTHON" == "3.9" || "$PYTHON" == "3.10" ]] ; then \
            if [ "$PYTHON" == "3.7" ] ; then \
                PYTHON_VERSION="3.7.${PYTHON_37_PATCH_VERSION}"; \
            elif [ "$PYTHON" == "3.8" ] ; then \
                    PYTHON_VERSION="3.8.${PYTHON_38_PATCH_VERSION}"; \
            elif [ "$PYTHON" == "3.9" ] ; then \
                    PYTHON_VERSION="3.9.${PYTHON_39_PATCH_VERSION}"; \
            elif [ "$PYTHON" == "3.10" ] ; then \
                    PYTHON_VERSION="3.10.${PYTHON_310_PATCH_VERSION}"; \
            fi &&  \
            dnf config-manager --enable powertools && \
            dnf -y update && \
            dnf -y install dnf-plugins-core && \
            dnf -y builddep python3 && \
            dnf -y install wget yum-utils make gcc openssl-devel bzip2-devel libffi-devel zlib-devel && \
            wget https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz && \
            tar xzf Python-${PYTHON_VERSION}.tgz && \
            cd Python-${PYTHON_VERSION} && \
            ./configure --enable-optimizations --enable-shared --libdir=/usr/local/lib LDFLAGS="-Wl,-rpath /usr/local/lib" && \
            make -j ${nproc} && \
            make install exec_prefix=/usr && \
            cd .. && rm -rf Python-${PYTHON_VERSION} && \
            if [ "$PYTHON" == "3.7" ] ; then \
                  cp -al /usr/include/python3.7m/pyconfig.h /usr/local/include/python3.7m/pyconfig.h && \
                  rm -rf /usr/include/python3.7m/ && \
                  ln -sf ../local/include/python3.7m /usr/include/python3.7m; \
            fi && \
            rm -rf Python-${PYTHON_VERSION}.tgz && \
            echo "/usr/local/lib" > /etc/ld.so.conf.d/python${PYTHON}.conf && \
            ldconfig && \
            alternatives --remove-all python && \
            alternatives --install /usr/bin/python python /usr/bin/python${PYTHON} 1 && \
            alternatives --remove-all python3 && \
            alternatives --install /usr/bin/python3 python3 /usr/bin/python${PYTHON} 1 && \
            python3 -m pip --no-cache-dir install --upgrade pip && \
            python3 -m pip --no-cache-dir install --upgrade setuptools wheel; \
        fi
    RUN python3 -m venv ${PYTHON_VENV}

FROM python as gfal2
    RUN dnf install -y epel-release.noarch && \
        dnf config-manager --enable powertools && \
        dnf -y update && \
        dnf -y install gfal2-devel && \
        if [ "$PYTHON" == "3.6" ] ; then \
            dnf -y install gfal2-python3;\
            cp /usr/lib64/python3.6/site-packages/gfal2.so /usr/lib64/gfal2.so; \
        elif [[ "$PYTHON" == "3.7" || "$PYTHON" == "3.8" || "$PYTHON" == "3.9" || "$PYTHON" == "3.10" ]] ; then \
            dnf install -y git && \ 
            git clone --depth 1 --branch v1.11.0 https://github.com/cern-fts/gfal2-python.git && \
            cd gfal2-python && \
            ./ci/fedora-packages.sh && \
            cd ./packaging && \
            RPMBUILD_SRC_EXTRA_FLAGS="--without docs --without python2" make srpm && \
            dnf -y builddep gfal2-python-1.11.0-1.el8.src.rpm && \
            cd ../ && \
            python3 -m pip --no-cache-dir install gfal2-python && \
            cd .. && rm -rf gfal2-python; \
            cp ${PYTHON_VENV}/lib/python${PYTHON}/site-packages/gfal2.so /usr/lib64/gfal2.so; \
        fi
    
FROM python as mod_wsgi
    RUN if [ "$PYTHON" == "3.6" ] ; then \
            dnf install -y python3-mod_wsgi && \
            cp /usr/lib64/httpd/modules/mod_wsgi_python3.so /usr/lib64/httpd/modules/mod_wsgi.so; \
        else \
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
    COPY tools tools
    COPY bin bin
    COPY lib lib
    COPY etc etc
    COPY .flake8 .pep8 .pycodestyle pylintrc setup.py setup_rucio.py setup_rucio_client.py setup_webui.py requirements.txt setuputil.py ./

    RUN dnf install -y epel-release.noarch && \
        dnf config-manager --enable powertools && \
        dnf module -y enable nodejs:16 && \
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

FROM rucio-runtime as requirements
    
    RUN dnf -y update && dnf -y install make gcc xmlsec1-devel xmlsec1-openssl-devel pkg-config libtool-ltdl-devel
    
    RUN python3 -m pip --no-cache-dir install --upgrade pip && \
        python3 -m pip --no-cache-dir install --upgrade setuptools wheel && \
        python3 -m pip --no-cache-dir install --upgrade -r requirements.txt
    
    COPY .flake8 .pep8 .pycodestyle pylintrc setup.py setup_rucio.py setup_rucio_client.py setup_webui.py ./
    RUN python3 -m pip --no-cache-dir install --upgrade .[oracle,postgresql,mysql,kerberos,saml,dev] && \
        python3 -m pip list

FROM rucio-runtime as final

    COPY --from=gfal2 /usr/include/gfal2 /usr/include/gfal2
    COPY --from=gfal2 /usr/lib64/* /usr/lib64/
    COPY --from=gfal2 /usr/lib64/gfal2.so /usr/lib64/gfal2.so

    RUN mv /usr/lib64/gfal2.so ${PYTHON_VENV}/lib/python${PYTHON}/site-packages/gfal2.so;
   
    COPY --from=oracle-client /usr/share/oracle /usr/share/oracle
    COPY --from=oracle-client /usr/lib/oracle /usr/lib/oracle/
    COPY --from=oracle-client /etc/ld.so.conf.d/oracle-instantclient.conf /etc/ld.so.conf.d/oracle-instantclient.conf
    
    COPY --from=requirements ${PYTHON_VENV} ${PYTHON_VENV}
    COPY --from=mod_wsgi /usr/lib64/httpd/modules /usr/lib64/httpd/modules
    COPY --from=mod_wsgi /etc/httpd/conf.modules.d/05-wsgi-python.conf  /etc/httpd/conf.modules.d/05-wsgi-python.conf 

    WORKDIR /opt/rucio
    RUN cp -r /usr/local/src/rucio/{lib,bin,tools,etc} ./

    RUN ldconfig
   
    CMD ["httpd","-D","FOREGROUND"]
