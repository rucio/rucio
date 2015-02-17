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
 * This loader is used for Rucio server log files after 12th, Nov 2014.
 *
 * Example log line: 128.142.143.183 [20/Dec/2014:01:11:31 +0100]  128.142.153.129 88905 "panda-/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=pandasv1/CN=531497/CN=Robot: ATLAS Panda Server1-unknown-dc04d4c1c872474f8844e37b472166db" VJS@s4COj8kAAH9zfSgAAAAD  "POST /replicas/list HTTP/1.1"  200 45326
 *
 * Extraced columns: loadbalacer_ip, timestamp, client_ip, responsetime_ms, account, remaining_auth_token, request_id, http_verb, uri, http_prorotcol, status, resp_size
 */

public class RucioServerLogs20141211 extends RegExLoader {
	private final static Pattern rucioLogPattern = Pattern
		.compile("^(\\S+)\\s+\\[(.*?)\\]\\s+(\\S+)\\s+(\\S+)\\s+\"(.*?)-(.*?)\"\\s+(\\S+)\\s+\"(\\S+) (\\S+) (\\S+)\"\\s+(\\S+)\\s+(\\S+)$");
		public Pattern getPattern() {
			return rucioLogPattern;
		}
	}
