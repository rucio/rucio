FROM rucio/rucio-systemd-cc7

# Set the working directory to /app
WORKDIR /tmp

# Copy the current directory contents into the container at /app
ADD . /tmp

RUN echo $HOSTNAME

RUN cat rucio.conf
RUN yum -y update
RUN yum clean all
RUN yum install -y epel-release.noarch
RUN yum install -y vim
RUN yum install -y gcc
RUN yum install -y httpd 
RUN yum install -y python-pip krb5-devel httpd mod_ssl mod_auth_kerb mod_wsgi python-devel.x86_64 openssl-devel.x86_64 gridsite libaio

RUN pip install rucio_webui

RUN rpm -i /tmp/oic.rpm
RUN echo "/usr/lib/oracle/12.1/client64/lib" >/etc/ld.so.conf.d/oracle.conf
RUN ldconfig
RUN yum install -y MySQL-python


VOLUME /var/log/httpd

RUN cp rucio.conf /etc/httpd/conf.d/rucio.conf
RUN cp httpd.conf /etc/httpd/conf/httpd.conf
RUN rm /etc/httpd/conf.d/ssl.conf /etc/httpd/conf.d/zgridsite.conf /etc/httpd/conf.d/welcome.conf /etc/httpd/conf.d/userdir.conf

RUN systemctl enable httpd.service
EXPOSE 443
CMD ["/usr/sbin/init"]

