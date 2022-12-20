#!/bin/bash
# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
export PASSPHRASE=123456

# Rucio Development CA
openssl genrsa -out rucio_ca.key.pem -passout env:PASSPHRASE 2048
openssl req -x509 -new -batch -key rucio_ca.key.pem -days 9999 -out rucio_ca.pem -subj "/CN=Rucio Development CA" -passin env:PASSPHRASE
hash=$(openssl x509 -noout -hash -in rucio_ca.pem)
ln -sf rucio_ca.pem $hash.0

# User certificate
openssl req -new -newkey rsa:2048 -nodes -keyout ruciouser.key.pem -subj "/CN=Rucio User" > ruciouser.csr
openssl x509 -req -days 9999 -CAcreateserial -extfile <(printf "keyUsage=critical") -in ruciouser.csr -CA rucio_ca.pem -CAkey rucio_ca.key.pem -out ruciouser.pem


# Rucio
openssl req -new -newkey rsa:2048 -nodes -keyout hostcert_rucio.key.pem -subj "/CN=rucio" > hostcert_rucio.csr
openssl x509 -req -days 9999 -CAcreateserial -extfile <(printf "subjectAltName=DNS:rucio,DNS:localhost") -in hostcert_rucio.csr -CA rucio_ca.pem -CAkey rucio_ca.key.pem -out hostcert_rucio.pem -passin env:PASSPHRASE


# FTS
openssl req -new -newkey rsa:2048 -nodes -keyout hostcert_fts.key.pem -subj "/CN=fts" > hostcert_fts.csr
openssl x509 -req -days 9999 -CAcreateserial -extfile <(printf "subjectAltName=DNS:fts,DNS:localhost") -in hostcert_fts.csr -CA rucio_ca.pem -CAkey rucio_ca.key.pem -out hostcert_fts.pem -passin env:PASSPHRASE


# XrootD Server 1
openssl req -new -newkey rsa:2048 -nodes -keyout hostcert_xrd1.key.pem -subj "/CN=xrd1" > hostcert_xrd1.csr
openssl x509 -req -days 9999 -CAcreateserial -extfile <(printf "subjectAltName=DNS:xrd1,DNS:localhost,DNS:xrd1.default.svc.cluster.local") -in hostcert_xrd1.csr -CA rucio_ca.pem -CAkey rucio_ca.key.pem -out hostcert_xrd1.pem -passin env:PASSPHRASE


# XrootD Server 2
openssl req -new -newkey rsa:2048 -nodes -keyout hostcert_xrd2.key.pem -subj "/CN=xrd2" > hostcert_xrd2.csr
openssl x509 -req -days 9999 -CAcreateserial -extfile <(printf "subjectAltName=DNS:xrd2,DNS:localhost,DNS:xrd2.default.svc.cluster.local") -in hostcert_xrd2.csr -CA rucio_ca.pem -CAkey rucio_ca.key.pem -out hostcert_xrd2.pem -passin env:PASSPHRASE


# XrootD Server 3
openssl req -new -newkey rsa:2048 -nodes -keyout hostcert_xrd3.key.pem -subj "/CN=xrd3" > hostcert_xrd3.csr
openssl x509 -req -days 9999 -CAcreateserial -extfile <(printf "subjectAltName=DNS:xrd3,DNS:localhost,DNS:xrd3.default.svc.cluster.local") -in hostcert_xrd3.csr -CA rucio_ca.pem -CAkey rucio_ca.key.pem -out hostcert_xrd3.pem -passin env:PASSPHRASE


# XrootD Server 4
openssl req -new -newkey rsa:2048 -nodes -keyout hostcert_xrd4.key.pem -subj "/CN=xrd4" > hostcert_xrd4.csr
openssl x509 -req -days 9999 -CAcreateserial -extfile <(printf "subjectAltName=DNS:xrd4,DNS:localhost,DNS:xrd4.default.svc.cluster.local") -in hostcert_xrd4.csr -CA rucio_ca.pem -CAkey rucio_ca.key.pem -out hostcert_xrd4.pem -passin env:PASSPHRASE


# WebDav Server 1
openssl req -new -newkey rsa:2048 -nodes -keyout hostcert_web1.key.pem -subj "/CN=web1" > hostcert_web1.csr
openssl x509 -req -days 9999 -CAcreateserial -extfile <(printf "subjectAltName=DNS:web1,DNS:localhost") -in hostcert_web1.csr -CA rucio_ca.pem -CAkey rucio_ca.key.pem -out hostcert_web1.pem -passin env:PASSPHRASE


# MinIO Server
openssl req -new -newkey rsa:2048 -nodes -keyout hostcert_minio.key.pem -subj "/CN=minio" > hostcert_minio.csr
openssl x509 -req -days 9999 -CAcreateserial -extfile <(printf "subjectAltName=DNS:minio,DNS:localhost") -in hostcert_minio.csr -CA rucio_ca.pem -CAkey rucio_ca.key.pem -out hostcert_minio.pem -passin env:PASSPHRASE

# SSH server
mkdir -p ssh
chmod 700 ssh
ssh-keygen -m PEM -t rsa -b 2048 -f ssh/ruciouser_sshkey -C 'ssh keys' -N ""

chmod 0400 *key*

echo
echo "cp rucio_ca.pem /etc/grid-security/certificates/$hash.0"
echo
