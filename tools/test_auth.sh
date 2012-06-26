# List DB contents
clear; for i in `sqlite3 /tmp/rucio.db ".tables"`; do echo $i:; sqlite3 /tmp/rucio.db "select * from $i"; echo; done

# Authenticate root via default x509 certificate
RAT_ROOT=`curl -s -i --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Account: root" -E /opt/rucio/etc/web/client.crt -X GET https://localhost/auth/x509 | grep Rucio-Auth-Token | awk '{print $2}'`
# Validate userpass token for root account
curl -v --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Auth-Token: $RAT_ROOT" -X GET https://localhost/auth/validate
# Create new user account
curl -v --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Auth-Token: $RAT_ROOT" -H "Rucio-Type: user" -d {} -X POST https://localhost/account/ddmlab

# Add userpass identity to user account
curl -v --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Auth-Token: $RAT_ROOT" -H "Rucio-Username: myusername" -H "Rucio-Password: secret" -X PUT https://localhost/identity/ddmlab/userpass
# Userpass login for user account
RAT_USER_USERPASS=`curl -s -i --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Account: ddmlab" -H "Rucio-Username: myusername" -H "Rucio-Password: secret" -X GET https://localhost/auth/x509 | grep Rucio-Auth-Token | awk '{print $2}'`
# Validate userpass token for user account
curl -v --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Auth-Token: $RAT_USER_USERPASS" -X GET https://localhost/auth/validate

# Add x509 certificate identity to user account
curl -v --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Auth-Token: $RAT_ROOT" -E ~/.globus/usercert.pem -X PUT https://localhost/identity/ddmlab/x509
# x509 login for user account
RAT_USER_X509=`curl -s -i --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Account: ddmlab" -E ~/.globus/usercert.pem -X GET https://localhost/auth/x509 | grep Rucio-Auth-Token | awk '{print $2}'`
# Validate x509 token for user account
curl -v --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Auth-Token: $RAT_USER_X509" -X GET https://localhost/auth/validate

# Add gss certificate identity to user account
curl -v --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Auth-Token: $RAT_ROOT" --negotiate -u: -X PUT https://localhost/identity/ddmlab/gss
# gss login for user account
RAT_USER_GSS=`curl -s -i --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Account: ddmlab" --negotiate -u: -X GET https://localhost/auth/x509 | grep Rucio-Auth-Token | awk '{print $2}'`
# Validate proxy token for user account
curl -v --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Auth-Token: $RAT_USER_GSS" -X GET https://localhost/auth/validate

# List DB contents
clear; for i in `sqlite3 /tmp/rucio.db ".tables"`; do echo $i:; sqlite3 /tmp/rucio.db "select * from $i"; echo; done
