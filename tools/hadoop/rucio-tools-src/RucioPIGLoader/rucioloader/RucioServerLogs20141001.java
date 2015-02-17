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
 * This loader is used for Rucio server log files from 1st, Oct 2014.
 *
 * Example log line: 
 * 128.142.132.133 [02/Oct/2014:01:04:56 +0200]  188.184.140.203 - 0 33280 "panda-/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=pandasv1/CN=531497/CN=Robot: ATLAS Panda Server1-unknown-04c3546df0d441faa09a23e63a0d14fe" VCyImICOj8kAAHOEUlAAAAEK  - "POST /replicas HTTP/1.1" 201 7
 *
 * Extraced columns: loadbalacer_ip, timestamp, client_ip, unknown, responsetime_s, responsetime_ms, account, remaining_auth_token, request_id, client_ref, http_verb, uri, http_prorotcol, status, resp_size
 */

public class RucioServerLogs20141001 extends RegExLoader {
	private final static Pattern rucioLogPattern = Pattern
		.compile("^(\\S+)\\s+\\[(.*?)\\]\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+\"(.*?)-(.*?)\"\\s+(\\S+)\\s+(\\S+)\\s+\"(\\S+) (\\S+) (\\S+)\"\\s+(\\S+)\\s+(\\S+)$");
		public Pattern getPattern() {
			return rucioLogPattern;
		}
	}
