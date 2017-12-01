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

RUN pip install rucio


RUN cp rucio.conf /etc/httpd/conf.d/rucio.conf; \
    cp httpd.conf /etc/httpd/conf/httpd.conf; \
    rm /etc/httpd/conf.d/ssl.conf /etc/httpd/conf.d/zgridsite.conf /etc/httpd/conf.d/welcome.conf /etc/httpd/conf.d/userdir.conf

VOLUME /var/log/httpd

RUN systemctl enable httpd.service
EXPOSE 443
CMD ["/usr/sbin/init"]

