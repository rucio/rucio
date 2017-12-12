# Copyright 2017
#   European Organization for Nuclear Research (CERN)
#   University of Oslo (Norway)
# for the benefit of the ATLAS collaboration
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2017
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2017
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2017
# - Frank Berghaus, <frank.berghaus@cern.ch>, 2017

FROM rucio/rucio-systemd-cc7

ADD etc/docker/dev/ca.repo /etc/yum.repos.d/ca.repo

RUN yum -y update
RUN yum clean all

RUN yum install -y ca-certificates.noarch
RUN yum install -y epel-release.noarch

RUN yum install -y gcc python-pip gmp-devel krb5-devel httpd mod_ssl mod_auth_kerb mod_wsgi git python-devel.x86_64 openssl-devel.x86_64 lcg-CA gridsite MySQL-python which

RUN pip install --upgrade pip

# Uncomment if oracle clients are needed (only works from inside CERN)
#RUN yum-config-manager --enable cernonly
#RUN yum install -y oracle-instantclient11.2-devel.x86_64 oracle-instantclient11.2-basic.x86_64 oracle-instantclient11.2-sqlplus.x86_64
#RUN echo "/usr/lib/oracle/11.2/client64/lib" >/etc/ld.so.conf.d/oracle.conf
#RUN ldconfig
#RUN pip install cx_Oracle

WORKDIR /opt

RUN mkdir /opt/rucio

COPY .pep8 /opt/rucio/
COPY .flake8 /opt/rucio/
COPY pylintrc /opt/rucio/

RUN mkdir /opt/rucio/bin
#COPY bin /opt/rucio/bin

RUN mkdir /opt/rucio/etc
COPY etc /opt/rucio/etc

RUN mkdir -p /opt/rucio/lib/rucio
#COPY lib/rucio /opt/rucio/lib/rucio

RUN mkdir /opt/rucio/tools
COPY tools /opt/rucio/tools

WORKDIR /opt/rucio

RUN pip install -r tools/pip-requires-client
RUN pip install -r tools/pip-requires
RUN pip install -r tools/pip-requires-test

RUN ln -s /opt/rucio/lib/rucio /usr/lib/python2.7/site-packages/rucio

ADD etc/docker/dev/rucio.cfg etc/
RUN cp etc/alembic.ini.template etc/alembic.ini
ADD etc/docker/dev/aliases-py27.conf etc/web/
RUN chmod 755 -R /opt/rucio/

RUN mkdir /var/log/rucio
RUN mkdir /var/log/rucio/trace
RUN chmod 777 /var/log/rucio

ADD etc/docker/dev/httpd.conf /etc/httpd/conf/httpd.conf
ADD etc/docker/dev/rucio.conf /etc/httpd/conf.d/rucio.conf

ADD etc/docker/dev/certs/ca.pem /opt/rucio/etc/web/CERN-bundle.pem
ADD etc/docker/dev/certs/ca.pem /opt/rucio/etc/web/ca.crt
ADD etc/docker/dev/certs/usercert.pem /opt/rucio/etc/web/usercert.pem

ADD etc/docker/dev/certs/server.crt /etc/grid-security/hostcert.pem
ADD etc/docker/dev/certs/server.key /etc/grid-security/hostkey.pem
RUN chmod 400 /etc/grid-security/hostkey.pem

WORKDIR /opt/rucio

RUN rm /etc/httpd/conf.d/ssl.conf /etc/httpd/conf.d/autoindex.conf /etc/httpd/conf.d/userdir.conf /etc/httpd/conf.d/welcome.conf

EXPOSE 443

ENV PATH $PATH:/opt/rucio/bin

RUN rm -rf /opt/rucio/tools && mkdir -p /opt/rucio/tools

CMD ["httpd","-D","FOREGROUND"]
