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
package rucioloader;

import java.util.regex.Pattern;
import org.apache.pig.piggybank.storage.RegExLoader;

/*
 * This loader is used for Rucio server log files after 3rd Jan 2015
 *
 * Example log line: 128.142.132.133 [04/Feb/2015:01:01:47 +0100]  128.142.132.49  20778 "panda-/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=pandasv1/CN=531497/CN=Robot: ATLAS Panda Server1-unknown-8ffa648995aa412a8d109ddc13900a17" VNFha4COj8kAABIZbPQAAAAC  "POST /replicas/list HTTP/1.1"  200 1796  rucio-clients/0.2.11  577 rucio-server-prod-01.cern.ch
 *
 * Extraced columns: loadbalacer_ip, timestamp, client_ip, responsetime_ms, account, remaining_auth_token, request_id, http_verb, uri, http_prorotcol, status, resp_size, user_agent, request_in_bytes, hostname
 */

public class RucioServerLogs20150203 extends RegExLoader {
	private final static Pattern rucioLogPattern = Pattern
		.compile("^(\\S+)\\s+\\[(.*?)\\]\\s+(\\S+)\\s+(\\S+)\\s+\"(.*?)-/(.*?)\"\\s+(\\S+)\\s+\"(\\S+) (\\S+) (\\S+)\"\\s+(\\S+)\\s+(\\S+)\\s+(.*?)\\s+(\\S+)\\s+(\\S+)$");
		public Pattern getPattern() {
			return rucioLogPattern;
		}
	}
