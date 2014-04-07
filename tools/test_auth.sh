curl -v -i --cacert /opt/rucio/etc/web/CERN-bundle.pem -H "X-Rucio-Account: root" -H "X-Rucio-Username: ddmlab" -H "X-Rucio-Password: secret" -X GET https://mlassnig-dev.cern.ch/auth/userpass

curl -v -i --cacert /opt/rucio/etc/web/CERN-bundle.pem -H "X-Rucio-Account: root" -E /opt/rucio/etc/web/usercert.pem -X GET https://mlassnig-dev.cern.ch/auth/x509

curl -v -i --cacert /opt/rucio/etc/web/CERN-bundle.pem -H "X-Rucio-Account: root" -E $X509_USER_PROXY -X GET https://mlassnig-dev.cern.ch/auth/x509_proxy

curl -v -i --cacert /opt/rucio/etc/web/CERN-bundle.pem -H "X-Rucio-Account: root" --negotiate -u: -X GET https://mlassnig-dev.cern.ch/auth/gss
