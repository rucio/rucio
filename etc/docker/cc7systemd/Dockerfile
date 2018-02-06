# Copyright European Organization for Nuclear Research (CERN) 2017
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2017
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2017

FROM centos:7
ENV container docker

WORKDIR /tmp
ADD . /tmp

# Configure systemd
RUN (cd /lib/systemd/system/sysinit.target.wants/; for i in *; do [ $i == \
systemd-tmpfiles-setup.service ] || rm -f $i; done); \
    rm -f /lib/systemd/system/multi-user.target.wants/*;\
    rm -f /etc/systemd/system/*.wants/*;\
    rm -f /lib/systemd/system/local-fs.target.wants/*; \
    rm -f /lib/systemd/system/sockets.target.wants/*udev*; \
    rm -f /lib/systemd/system/sockets.target.wants/*initctl*; \
    rm -f /lib/systemd/system/basic.target.wants/*;\
    rm -f /lib/systemd/system/anaconda.target.wants/*;

RUN yum install -y epel-release.noarch

# Install dependencies for rucio
RUN yum install -y \
    gcc \
    gridsite \
    httpd \
    krb5-devel \
    libaio \
    mod_auth_kerb \
    mod_ssl \
    mod_wsgi \
    openssl-devel.x86_64 \
    python-devel.x86_64 \
    python-pip \
    vim

# DB packages
# Oracle
RUN rpm -i /tmp/oic.rpm; \
    echo "/usr/lib/oracle/12.2/client64/lib" >/etc/ld.so.conf.d/oracle.conf; \
    ldconfig
RUN pip install cx_Oracle
# MySQL
RUN yum install -y MySQL-python
# Postgres
RUN yum install -y python-psycopg2.x86_64

VOLUME [ "/sys/fs/cgroup" ]
CMD ["/usr/sbin/init"]

