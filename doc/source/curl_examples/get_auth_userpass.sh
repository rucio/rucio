curl -s -i --cacert /opt/rucio/etc/web/ca.crt  -X GET -H "Rucio-Account: root" -H "Rucio-Username: ddmlab" -H "Rucio-Password: secret" https://localhost/auth/userpass 
