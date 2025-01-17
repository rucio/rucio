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

DAYS=9000

# Rucio Development CA
openssl genrsa -out rucio_ca.key.pem -passout env:PASSPHRASE 2048
openssl req -x509 -new -batch -key rucio_ca.key.pem -days $DAYS -out rucio_ca.pem -subj "/CN=Rucio Development CA" -passin env:PASSPHRASE
hash=$(openssl x509 -noout -hash -in rucio_ca.pem)
ln -sf rucio_ca.pem $hash.0

# User certificate.
openssl req -new -newkey rsa:2048 -noenc -keyout ruciouser.key.pem -subj "/CN=Rucio User" > ruciouser.csr
openssl x509 -req -days $DAYS -CAcreateserial -extfile <(printf "keyUsage = critical, digitalSignature, keyEncipherment") -in ruciouser.csr -CA rucio_ca.pem -CAkey rucio_ca.key.pem -out ruciouser.pem
cat "ruciouser.pem" "ruciouser.key.pem" > "ruciouser.certkey.pem"

# The service certificates
for CN in rucio fts xrd1 xrd2 xrd3 xrd4 xrd5 minio indigoiam keycloak web1 dirac-server
do
  SAN="subjectAltName=DNS:$CN,DNS:localhost,DNS:$CN.default.svc.cluster.local"
  openssl req -new -newkey rsa:2048 -noenc -keyout "hostcert_$CN.key.pem" -subj "/CN=$CN" > "hostcert_$CN.csr"
  openssl x509 -req -days $DAYS -CAcreateserial -extfile <(printf "%s" "$SAN") -in "hostcert_$CN.csr" -CA rucio_ca.pem -CAkey rucio_ca.key.pem -out "hostcert_$CN.pem" -passin env:PASSPHRASE
done

cat "hostcert_rucio.pem" "hostcert_rucio.key.pem" > "hostcert_rucio.certkey.pem"

rm ./*.csr

# SSH server
mkdir -p ssh
rm -f ssh/ruciouser_sshkey* && ssh-keygen -m PEM -t rsa -b 2048 -f ssh/ruciouser_sshkey -C 'ssh keys' -N ""

echo
echo "cp rucio_ca.pem /etc/grid-security/certificates/$hash.0"
echo
