kinit
curl -s -i --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Account: ddmlab" --negotiate -u: -X GET https://localhost/auth/gss
