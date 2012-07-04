curl -s -i --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Account: root" -E /opt/rucio/etc/web/client.crt -X GET https://localhost/auth/x509
