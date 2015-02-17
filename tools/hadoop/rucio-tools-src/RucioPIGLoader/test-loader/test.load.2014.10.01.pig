REGISTER /usr/lib/pig/piggybank.jar;
REGISTER /usr/lib/pig/pig.jar;
REGISTER /data/HttpMonitoring/rucioloader.jar;


logs = LOAD '/user/rucio01/logs/2014-11-14/*server-prod-02*/access*' USING rucioloader.RucioServerLogs20141001 AS (loadbalacer_ip, timestamp, client_ip, unknown, responsetime_s, responsetime_ms, account, remaining_auth_token, request_id, client_ref, http_verb, uri, http_prorotcol, status, resp_size);

DUMP logs;

