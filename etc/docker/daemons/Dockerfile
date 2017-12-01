# Copyright European Organization for Nuclear Research (CERN) 2017
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2017

FROM rucio/rucio-systemd-cc7
ENV container docker


# Set the working directory to /app
WORKDIR /tmp

# Copy the current directory contents into the container at /app
ADD . /tmp

# Install Rucio
RUN pip install rucio

# Install dependecies
RUN yum install -y \
    gfal2 \
    gfal2-plugin-file \
    gfal2-plugin-gridftp \
    gfal2-plugin-http \
    gfal2-plugin-srm \
    gfal2-plugin-xrootd \
    gfal2-python \
    supervisor

RUN cp supervisord.conf /etc/supervisord.conf

VOLUME /var/log/rucio

RUN systemctl enable supervisord.service
CMD ["/usr/sbin/init"]
