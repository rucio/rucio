# Copyright European Organization for Nuclear Research (CERN) 2017
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2017


FROM rucio/rucio-systemd-cc7

# Set the working directory to /app
WORKDIR /tmp

# Copy the current directory contents into the container at /app
ADD . /tmp

RUN yum install -y epel-release.noarch
RUN yum install -y python-pip krb5-devel httpd mod_ssl mod_auth_kerb mod_wsgi python-devel.x86_64 openssl-devel.x86_64 gridsite libaio
RUN rpm -i /tmp/oic.rpm
RUN echo "/usr/lib/oracle/12.1/client64/lib" >/etc/ld.so.conf.d/oracle.conf
RUN ldconfig
RUN yum install -y vim
RUN yum install -y gcc
RUN yum install -y httpd 
RUN yum install -y MySQL-python
RUN pip install rucio
RUN yum install -y gfal2 gfal2-plugin-file gfal2-plugin-http gfal2-plugin-srm gfal2-python gfal2-plugin-gridftp gfal2-plugin-xrootd
RUN yum install -y supervisor
RUN cp supervisord.conf /etc/supervisord.conf

VOLUME /var/log/rucio

RUN systemctl enable supervisord.service
CMD ["/usr/sbin/init"]

