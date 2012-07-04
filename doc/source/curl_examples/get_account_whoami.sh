TOKEN=`curl -s -i --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Account: root" -E /opt/rucio/etc/web/client.crt -X GET https://localhost/auth/x509 | grep Rucio-Auth-Token | awk '{print $2}'`
curl -s -i -L --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Auth-Token: $TOKEN" -X GET https://localhost/account/whoami
