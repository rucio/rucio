/* Copyright European Organization for Nuclear Research (CERN)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Authors:
 * - Ralph Vigne <ralph.vigne@cern.ch>, 2015
*/
REGISTER /data/rucioudfs.jar;
REGISTER /usr/lib/pig/piggybank.jar;
REGISTER /usr/lib/pig/pig.jar;


logs = LOAD '/user/rucio01/logs/server/access*$date*' USING rucioudfs.RucioServerLogs20150211 AS (
  timestamp,
  backendname,
  loadbalancer,
  client,
  requestID,
  status,
  request_bytes,
  response_bytes,
  response_time,
  http_verb,
  resource,
  protocol,
  account,
  certificate,
  useragent,
  app_id
);

reduced_cols = FOREACH logs GENERATE REGEX_EXTRACT(timestamp, '^(.*?) (.*)$', 1) as time,
  account,
  response_time,
  response_bytes;

filtered = FILTER reduced_cols BY time == '$date' AND account != '';

grouped = GROUP filtered BY (time, account);

report = FOREACH grouped GENERATE  group.time,
  group.account,
  COUNT(filtered) as nb,
  (long)SUM(filtered.response_bytes) as sum_resp_bytes,
  (long)SUM(filtered.response_time) as sum_resp_time;

final_results = ORDER report BY time desc, sum_resp_time desc;

STORE final_results INTO 'tmp/requests_daily/per_account.csv';
