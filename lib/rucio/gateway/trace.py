# Copyright European Organization for Nuclear Research (CERN) since 2012
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime
import json
import uuid
from typing import Optional

from rucio.core.trace import trace as core_trace


def trace(request: bytes, trace_ip: Optional[str]) -> None:
    """
    Sends the trace data to trace broker after adding additional fields
    Adds the following fields:
        - 'traceTimeentry': The current UTC timestamp.
        - 'traceTimeentryUnix': The Unix timestamp with microsecond precision.
        - 'traceIp': The client's IP address, either from 'X-Forwarded-For' header or remote address.
        - 'traceId': A unique identifier for the trace, generated as a UUID without hyphens.

    Args:
        request_data: Request json given by client
        trace_ip: TraceIP, either the client's IP address, or IP from "X-Forwarded-For" header
    """
    request_data = json.loads(request)
    if isinstance(request_data, dict):
        request_data = [request_data]

    for item in request_data:
        item["traceIp"] = trace_ip
        # generate entry timestamp
        item["traceTimeentry"] = datetime.datetime.now(datetime.timezone.utc)
        item["traceTimeentryUnix"] = item["traceTimeentry"].timestamp()
        # generate unique ID
        item["traceId"] = str(uuid.uuid4()).replace("-", "").lower()

        core_trace(payload=item)
