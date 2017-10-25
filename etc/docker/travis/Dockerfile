FROM cern/cc7-base

RUN yum -y update
RUN yum clean all

RUN yum install -y epel-release.noarch

RUN yum install -y gcc

RUN yum install -y httpd 
RUN yum install -y python-pip gmp-devel krb5-devel httpd mod_ssl mod_auth_kerb mod_wsgi git python-devel.x86_64 openssl-devel.x86_64 gridsite which MySQL-python libaio

WORKDIR /opt

RUN mkdir /opt/rucio

COPY .pep8 /opt/rucio/
COPY pylintrc /opt/rucio/

RUN mkdir /opt/rucio/bin
COPY bin /opt/rucio/bin

RUN mkdir /opt/rucio/etc
COPY etc /opt/rucio/etc

RUN mkdir -p /opt/rucio/lib/rucio
COPY lib/rucio /opt/rucio/lib/rucio

RUN mkdir /opt/rucio/tools
COPY tools /opt/rucio/tools

WORKDIR /opt/rucio

RUN yum install -y /opt/rucio/etc/docker/travis/oic.rpm
RUN echo "/usr/lib/oracle/12.2/client64/lib" >/etc/ld.so.conf.d/oracle.conf
RUN ldconfig

RUN pip install --upgrade pip
RUN pip install -r tools/pip-requires-client
RUN pip install -r tools/pip-requires
RUN pip install -r tools/pip-requires-test
RUN pip install cx_Oracle

RUN ln -s /opt/rucio/lib/rucio /usr/lib/python2.7/site-packages/rucio

ADD etc/docker/travis/rucio_oracle.cfg etc/rucio.cfg
RUN cp etc/alembic.ini.template etc/alembic.ini
ADD etc/docker/travis/aliases-py27.conf etc/web/

RUN mkdir /var/log/rucio
RUN mkdir /var/log/rucio/trace
RUN chmod 777 /var/log/rucio

ADD etc/docker/travis/httpd.conf /etc/httpd/conf/httpd.conf
ADD etc/docker/travis/rucio.conf /etc/httpd/conf.d/rucio.conf

ADD etc/docker/travis/certs/ca.pem /opt/rucio/etc/web/CERN-bundle.pem
ADD etc/docker/travis/certs/ca.pem /opt/rucio/etc/web/ca.crt
ADD etc/docker/travis/certs/usercert.pem /opt/rucio/etc/web/usercert.pem

ADD etc/docker/travis/certs/server.crt /etc/grid-security/hostcert.pem
ADD etc/docker/travis/certs/server.key /etc/grid-security/hostkey.pem
RUN chmod 400 /etc/grid-security/hostkey.pem

RUN rm /etc/httpd/conf.d/ssl.conf /etc/httpd/conf.d/autoindex.conf /etc/httpd/conf.d/userdir.conf /etc/httpd/conf.d/welcome.conf

ENV PATH $PATH:/opt/rucio/bin

CMD ["/usr/sbin/init"]
