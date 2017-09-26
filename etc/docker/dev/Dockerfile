FROM cern/cc7-base

ADD etc/docker/ca.repo /etc/yum.repos.d/ca.repo

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

RUN pip install -r tools/pip-requires-client
RUN pip install -r tools/pip-requires
RUN pip install -r tools/pip-requires-test

RUN ln -s /opt/rucio/lib/rucio /usr/lib/python2.7/site-packages/rucio

ADD etc/docker/dev/rucio.cfg etc/
RUN cp etc/alembic.ini.template etc/alembic.ini
ADD etc/docker/dev/aliases-py27.conf etc/web/

RUN mkdir /var/log/rucio
RUN mkdir /var/log/rucio/trace
RUN chmod 777 /var/log/rucio

ADD etc/docker/dev/httpd.conf /etc/httpd/conf/httpd.conf
ADD etc/docker/dev/rucio.conf /etc/httpd/conf.d/rucio.conf

ADD etc/web/CERN-bundle.pem /opt/rucio/etc/web/CERN-bundle.pem
ADD etc/web/ca.crt /opt/rucio/etc/web/ca.crt
ADD etc/web/client.crt /opt/rucio/etc/web/usercert.pem

ADD etc/docker/dev/hostcert.pem /etc/grid-security/hostcert.pem
ADD etc/docker/dev/hostkey.pem /etc/grid-security/hostkey.pem
RUN chmod 400 /etc/grid-security/hostkey.pem

RUN rm /etc/httpd/conf.d/ssl.conf /etc/httpd/conf.d/autoindex.conf /etc/httpd/conf.d/userdir.conf /etc/httpd/conf.d/welcome.conf

EXPOSE 443

ENV PATH $PATH:/opt/rucio/bin

RUN systemctl enable httpd.service
CMD ["/usr/sbin/init"]
