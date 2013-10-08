echo 'select the proxy'
export USERPROXY=/home/mario/dev/rucio/tools/rucio01.proxy

echo 'retrieving FTS3 user information'
curl -s --cacert /opt/rucio/etc/web/ca.crt -E $USERPROXY -X GET https://fts3-pilot.cern.ch:8446/whoami

echo 'checking FTS3 lifetime'
curl -s --cacert /opt/rucio/etc/web/ca.crt -E $USERPROXY -X GET https://fts3-pilot.cern.ch:8446/delegation/592d0a09295e9451

echo 'requesting certificate signing request'
curl -s --cacert /opt/rucio/etc/web/ca.crt -E $USERPROXY -X GET https://fts3-pilot.cern.ch:8446/delegation/592d0a09295e9451/request >request.pem

echo 'signing the request'
rm -rf demoCA
mkdir -p demoCA/newcerts
touch demoCA/index.txt
echo "00" >demoCA/serial
openssl ca -in request.pem -preserveDN -days 365 -cert $USERPROXY -keyfile $USERPROXY -md sha1 -out proxy.pem -subj '/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=rucio01/CN=663551/CN=Robot: Rucio Service Account 01/CN=proxy/CN=proxy' -policy policy_anything -batch

echo 'uploading the signed request'
cat $USERPROXY proxy.pem > full.pem
curl -s --cacert /opt/rucio/etc/web/ca.crt -E $USERPROXY -X PUT -T full.pem https://fts3-pilot.cern.ch:8446/delegation/592d0a09295e9451/credential

echo 'checking FTS3 lifetime'
curl -s --cacert /opt/rucio/etc/web/ca.crt -E $USERPROXY -X GET https://fts3-pilot.cern.ch:8446/delegation/592d0a09295e9451

echo 'done'
