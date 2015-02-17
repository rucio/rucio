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
 * This loader is used for Rucio server log files after 8th Jan 2015
 *
 * Example log line: 128.142.132.133 [20/Jan/2015:00:22:10 +0100]  128.142.200.115 27497 "panda-/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=pandasv1/CN=531497/CN=Robot: ATLAS Panda Server1-unknown-11ece375289a41c18d7d9dbd4685d63f" VL2RooCOj8kAAFc4QYAAAADB  "POST /replicas/list HTTP/1.1"  200 2004  python-requests/2.4.1 CPython/2.6.6 Linux/2.6.32-504.3.3.el6.x86_64
 *
 * Extraced columns: loadbalacer_ip, timestamp, client_ip, responsetime_ms, account, remaining_auth_token, request_id, http_verb, uri, http_prorotcol, status, resp_size, user_agent
 */

public class RucioServerLogs20150108 extends RegExLoader {
	private final static Pattern rucioLogPattern = Pattern
		.compile("^(\\S+)\\s+\\[(.*?)\\]\\s+(\\S+)\\s+(\\S+)\\s+\"(.*?)-(.*?)\"\\s+(\\S+)\\s+\"(\\S+) (\\S+) (\\S+)\"\\s+(\\S+)\\s+(\\S+)\\s+(.*?)$");
		public Pattern getPattern() {
			return rucioLogPattern;
		}
	}
