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
package rucioudfs;

import java.util.regex.Pattern;
import org.apache.pig.piggybank.storage.RegExLoader;

/*
 * This loader is used for Rucio server log files after 3rd Jan 2015
 *
 * Example log line: [2015-02-11 14:19:03]	rucio-server-prod-01.cern.ch	128.142.132.133	188.184.140.203	VNtWx4COj8kAAGLgFFMAAABC	201	1583	7	113539	"POST /dids/attachments HTTP/1.1"	"panda-/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=pandasv1/CN=531497/CN=Robot: ATLAS Panda Server1-unknown-986ec3ba038942c5ad64cd46537531a7"	"rucio-clients/0.2.11"
 *
 * Extraced columns: loadbalacer_ip, timestamp, client_ip, responsetime_ms, account, remaining_auth_token, request_id, http_verb, uri, http_prorotcol, status, resp_size, user_agent, request_in_bytes, hostname
 */

public class RucioServerLogs20150603 extends RegExLoader {

	private final static Pattern rucioLogPattern = Pattern
		.compile("^\\[(.*?)\\]\t(\\S+)\t(\\S+)\t(.*?)\t(\\S+)\t(\\S+)\t(\\S+)\t(\\S+)\t(\\S+)\t\"(\\S+)\\s+(\\S+)\\s+(\\S+)\"\t\"(.*?)-/(.*?)\"\t\"(.*?)\"\t?(.*)?$");
		public Pattern getPattern() {
			return rucioLogPattern;
		}
	}
