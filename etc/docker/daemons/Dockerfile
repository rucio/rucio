# Copyright European Organization for Nuclear Research (CERN) 2017
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2017
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2018

FROM centos:7

WORKDIR /tmp
ADD oic.rpm /tmp

RUN yum install -y epel-release.noarch
RUN yum upgrade -y
RUN yum install -y python-pip libaio gcc python-devel.x86_64

RUN rpm -i /tmp/oic.rpm; \
    echo "/usr/lib/oracle/12.2/client64/lib" >/etc/ld.so.conf.d/oracle.conf; \
    ldconfig
RUN pip install --upgrade pip setuptools
RUN pip install rucio[oracle,mysql,postgresql]==1.16.0.post1 j2cli

# Install dependecies
RUN yum install -y \
    gfal2 \
    gfal2-plugin-file \
    gfal2-plugin-gridftp \
    gfal2-plugin-http \
    gfal2-plugin-srm \
    gfal2-plugin-xrootd \
    gfal2-python

ADD start-daemon.sh /

RUN mkdir /var/log/rucio

VOLUME /var/log/rucio
VOLUME /opt/rucio/etc

ENTRYPOINT ["/start-daemon.sh"]
