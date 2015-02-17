REGISTER /usr/lib/pig/piggybank.jar;
REGISTER /usr/lib/pig/pig.jar;
REGISTER /data/HttpMonitoring/rucioloader.jar;



logs = LOAD '/user/rucio01/logs/server/access*server-prod-01*2015-02-12' USING rucioloader.RucioServerLogs20150211 AS (timestamp, backendname, loadbalancer, client, requestID, status, request_bytes, response_bytes, response_time, http_verb, resource, protocol, account, certificate, useragent);

DUMP logs;
