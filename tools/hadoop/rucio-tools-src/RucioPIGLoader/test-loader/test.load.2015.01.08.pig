REGISTER /usr/lib/pig/piggybank.jar;
REGISTER /usr/lib/pig/pig.jar;
REGISTER /data/HttpMonitoring/rucioloader.jar;


logs = LOAD '/user/rucio01/logs/2015-01-14/*server-prod-02*/access*' USING rucioloader.RucioServerLogs20150108 AS (loadbalacer_ip, timestamp, client_ip, responsetime_ms, account, remaining_auth_token, request_id, http_verb, uri, http_prorotcol, status, resp_size, user_agent);

DUMP logs;

