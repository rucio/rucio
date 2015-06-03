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


logs = LOAD '/user/rucio01/logs/server/access*$date*' USING rucioudfs.RucioServerLogs20150603 AS (
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
  script_id
);


reduced_cols = FOREACH logs GENERATE REGEX_EXTRACT(timestamp, '^(.*?) (.*)$', 1) as time,
  account,
  client,
  script_id,
  response_bytes,
  response_time;

grouped = GROUP reduced_cols BY (time, account, client, script_id);

report = FOREACH grouped GENERATE  group.time,
  group.account,
  group.client,
  group.script_id,
  COUNT(reduced_cols) as nb,
  (long)SUM(reduced_cols.response_bytes) as sum_resp_bytes,
  (long)SUM(reduced_cols.response_time) as sum_resp_time;

final_results = ORDER report BY time desc, nb desc;

STORE final_results INTO 'tmp/requests_daily/per_country.csv';
