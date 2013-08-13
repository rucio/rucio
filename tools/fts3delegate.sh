#!/bin/bash

FTSHOST=https://fts3-pilot.cern.ch:8446
USERCERT=/home/mario/.globus/usercert.pem
USERKEY=/home/mario/.globus/userkey.pem
USERCERTKEY=/home/mario/.globus/cert_and_key.pem
USERPROXY=/opt/rucio/etc/web/x509up
CURL='curl -s --cacert /opt/rucio/etc/web/ca.crt -E /opt/rucio/etc/web/x509up'

DELEGATION_ID=$($CURL -X GET $FTSHOST/whoami | grep delegation_id | cut -d'"' -f4)
LIFETIME=$($CURL -X GET $FTSHOST/delegation/$DELEGATION_ID | grep termination_time)

echo $DELEGATION_ID lifetime: $LIFETIME

$CURL -X GET $FTSHOST/delegation/$DELEGATION_ID/request > request.pem

openssl x509 -req -sha1 -CAcreateserial -in request.pem -days 1 -CA /opt/rucio/etc/web/x509up -CAkey /opt/rucio/etc/web/x509up -out proxy.pem

$CURL -X PUT -T proxy.pem $FTSHOST/delegation/$DELEGATION_ID/credential
