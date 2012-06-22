# Authenticate root via default x509 certificate
RAT_ROOT=`curl -s -i --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Account: root" -E /opt/rucio/etc/web/client.crt -X GET https://localhost/auth/x509 | grep Rucio-Auth-Token | awk '{print $2}'`
echo $RAT_ROOT

# Validate userpass token for root account
curl -v --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Auth-Token: $RAT_ROOT" -X GET https://localhost/auth/validate

# Create new user account
curl -v --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Auth-Token: $RAT_ROOT" -H "Rucio-Type: user" -d {} -X POST https://localhost/account/mlassnig

# Add userpass identity to user account
curl -v --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Auth-Token: $RAT_ROOT" -H "Rucio-Username: mario" -H "Rucio-Password: secret" -X PUT https://localhost/identity/mlassnig/userpass

# Add x509 certificate identity to user account
curl -v --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Auth-Token: $RAT_ROOT" -E ~/.globus/usercert.pem -X PUT https://localhost/identity/mlassnig/x509

# Add x509 proxy identity to user account
curl -v --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Auth-Token: $RAT_ROOT" -E /opt/rucio/etc/web/mlassnig.proxy -X PUT https://localhost/identity/mlassnig/x509

# Userpass login for user account
RAT_USER_USERPASS=`curl -s -i --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Account: mlassnig" -H "Rucio-Username: mario" -H "Rucio-Password: secret" -X GET https://localhost/auth/x509 | grep Rucio-Auth-Token | awk '{print $2}'`

# x509 login for user account
RAT_USER_X509=`curl -s -i --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Account: mlassnig" -E ~/.globus/usercert.pem -X GET https://localhost/auth/x509 | grep Rucio-Auth-Token | awk '{print $2}'`

# proxy login for user account
RAT_USER_PROXY=`curl -s -i --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Account: mlassnig" -E /opt/rucio/etc/web/mlassnig.proxy -X GET https://localhost/auth/x509 | grep Rucio-Auth-Token | awk '{print $2}'`

# Validate userpass token for user account
curl -v --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Auth-Token: $RAT_USER_USERPASS" -X GET https://localhost/auth/validate

# Validate x509 token for user account
curl -v --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Auth-Token: $RAT_USER_X509" -X GET https://localhost/auth/validate

# Validate proxy token for user account
curl -v --cacert /opt/rucio/etc/web/ca.crt -H "Rucio-Auth-Token: $RAT_USER_PROXY" -X GET https://localhost/auth/validate
