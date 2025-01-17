FROM almalinux:9

ARG DIRACOS_VERSION="2.48"
ARG DIRAC_VERSION="8.0.62"
ARG RUCIO_VERSION="36.1.0"
ARG USERID=1000
ARG GROUPID=1000

RUN dnf install -y \
        procps-ng \
        psmisc \
        openssh-clients \
        iptables-services \
        https://diracproject.web.cern.ch/diracproject/rpm/runit-2.1.2-2.el9.x86_64.rpm

COPY ./runsvdir-start.service /usr/lib/systemd/system/runsvdir-start.service
RUN systemctl enable runsvdir-start

RUN \
  if getent group ${GROUPID}; then \
    groupmod --new-name dirac $(getent group ${GROUPID} | cut -d: -f1); \
  else \
    groupadd --gid ${GROUPID} dirac; \
  fi\
  && adduser --uid ${USERID} --gid dirac -s /bin/bash -d /home/dirac dirac

RUN mkdir -p /opt/dirac/etc/grid-security/certificates && chown -R dirac:dirac /opt/dirac
RUN mkdir -p /etc/grid-security/certificates && chown -R dirac:dirac /etc/grid-security

# run everything here as dirac user to get correct permissions
USER dirac


# install diracos
WORKDIR /home/dirac
ENV DIRAC_ROOT_PATH=/opt/dirac
ENV DIRACOS="${DIRAC_ROOT_PATH}/diracos"

RUN \
  curl -sSfLO "https://github.com/DIRACGrid/DIRACOS2/releases/download/${DIRACOS_VERSION}/DIRACOS-Linux-x86_64.sh" \
  && bash "DIRACOS-Linux-x86_64.sh" -p ${DIRACOS} \
  && rm "DIRACOS-Linux-x86_64.sh" \
  && source "${DIRACOS}/diracosrc" \
  && micromamba clean --all --yes \
  && pip install --no-cache-dir DIRAC==${DIRAC_VERSION} WebAppDIRAC[server] rucio-clients==${RUCIO_VERSION}

RUN mkdir -p /opt/dirac/etc/grid-security/certificates \
  && mkdir -p /home/dirac/.ssh
COPY --chown=dirac:dirac ./runsvdir-start /opt/dirac/sbin/runsvdir-start
COPY --chown=dirac:dirac ./configure.py ./resources.conf ./install_site.sh /home/dirac/
COPY --chown=dirac:dirac ./bashrc ./dirac-installation.cfg /opt/dirac/

# switch back to root for running systemd
USER root
CMD ["/usr/sbin/init"]

ENV \
  DIRAC="${DIRACOS}" \
  CONDA_PREFIX="${DIRACOS}" \
  CONDOR_CONFIG="${DIRACOS}/etc/condor/condor_config" \
  DAVIX_DISABLE_REDIRECT_CACHING=1 \
  DAVIX_USE_LIBCURL=1 \
  GSETTINGS_SCHEMA_DIR="${DIRACOS}/share/glib-2.0/schemas" \
  MAMBA_ROOT_PREFIX="${DIRACOS}" \
  PATH="${DIRACOS}/bin:${PATH}" \
  X509_CERT_DIR="/etc/grid-security/certificates" \
  X509_VOMSES="${DIRACOS}/etc/grid-security/vomses" \
  X509_VOMS_DIR="${DIRACOS}/etc/grid-security/vomsdir" \
  XML_CATALOG_FILES="file://${DIRACOS}/etc/xml/catalog file:///etc/xml/catalog"
