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

REGISTER rucioloader.jar;
REGISTER /usr/lib/pig/piggybank.jar;
REGISTER /usr/lib/pig/pig.jar;


logs = LOAD '/user/rucio01/logs/server/access*$date*' USING rucioloader.RucioServerLogs20150211 AS (
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
	useragent
);

reduced_cols = FOREACH logs GENERATE REGEX_EXTRACT(timestamp, '^(.*?) (.*)$', 1) as time, 
					account, 
					CONCAT(CONCAT(http_verb,' '), resource) as request,
					response_time,
					response_bytes;

dids = FILTER reduced_cols BY REGEX_EXTRACT(request, '(.*?)\\/(.*?)($|(\\/.*?$))', 2) == 'dids' AND account != '' AND time =='$date';
rest = FILTER reduced_cols BY REGEX_EXTRACT(request, '(.*?)\\/(.*?)($|(\\/.*?$))', 2) != 'dids' AND account != '' AND time =='$date';

matched_dids = FOREACH dids GENERATE time, account, REGEX_EXTRACT(request, '^(\\S+\\s+(\\/[^\\/]*){0,3})(.*)$', 1) as grp_uri, response_time, response_bytes;
matched_rest = FOREACH rest GENERATE time, account, REGEX_EXTRACT(request, '^(\\S+\\s+(\\/[^\\/]*){0,2})(.*)$', 1) as grp_uri, response_time, response_bytes;

unioned = UNION matched_dids, matched_rest;

grouped = GROUP unioned BY (time, account, grp_uri); 

report = FOREACH grouped GENERATE  group.time,
					group.account,
					group.grp_uri,
					COUNT(unioned) as nb,
					(long)SUM(unioned.response_bytes) as sum_resp_bytes,
					(long)SUM(unioned.response_time) as sum_resp_time;

final_results = ORDER report BY time desc, sum_resp_time desc;

STORE final_results INTO 'tmp/requests_daily/account_details.csv';
