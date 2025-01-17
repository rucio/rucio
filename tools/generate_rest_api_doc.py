#!/usr/bin/env python3
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

from apispec import APISpec
from apispec_webframeworks.flask import FlaskPlugin

from rucio.api.flaskapi.v1.main import application
from rucio.core.vcsversion import VERSION_INFO

description_text = """Each resource can be accessed or modified using specially
formed URLs and the standard HTTP methods:

- GET to read

- POST to create

- PUT to update

- DELETE to remove

We require that all requests are done over SSL. The API supports JSON
formats. Rucio uses [OAuth](http://oauth.net/) to authenticate all API
requests. The method is to get an authentication token, and use it for the rest
of the requests. Descriptions of the actions you may perform on each resource
can be found below.

### Date format

All dates returned are in UTC and are strings in the following format (RFC 1123,
ex RFC 822):

```
Mon, 13 May 2013 10:23:03 UTC
```

In code format, which can be used in all programming languages that support
strftime or strptime:

```
%a, %d %b %Y %H:%M:%S UTC
```

### SSL only

We require that all requests(except for the ping) are done over SSL.

### Response formats

The currently-available response format for all REST endpoints is the
string-based format JavaScript Object
Notation([JSON](http://www.json.org/)). The server answer can be one of the
following content-type in the http Header:

```text
Content-type: application/json
Content-Type: application/x-json-stream
```

In the last case, it corresponds to JSON objects delimited by newlines(streaming
JSON for large answer), e.g.:

```
{ "id": 1, "foo": "bar" } { "id": 2, "foo": "baz" } ...
```

### Error handling

Errors are returned using standard HTTP error code syntax.  Any additional info
is included in the header of the return call, JSON-formatted with the
parameters:

```
ExceptionClass ExceptionMessage
```

Where ExceptionClass refers to [`Rucio
Exceptions`](rucio-core/src/rucio/core/common/exception.py).
"""


spec = APISpec(
    title="Rucio",
    version=VERSION_INFO['version'],
    openapi_version="3.0.2",
    plugins=[FlaskPlugin()],
    info={
        "description": description_text,
        "license": {
            "name": "Apache 2.0",
            "url": "https://www.apache.org/licenses/LICENSE-2.0.html",
        },
        "x-logo": {
            "url": "http://rucio.cern.ch/documentation/img/rucio_horizontaled_black_cropped.svg",
            "backgroundColor": "#FFFFFF",
            "altText": "Rucio logo"
        },
    },
    # See: https://swagger.io/docs/specification/authentication/api-keys/
    components={
        "securitySchemes": {
            "AuthToken": {
                "type": "apiKey",
                "in": "header",
                "name": "X-Rucio-Auth-Token",
                "description": "The Rucio Token obtained by one of the /auth endpoints."
            },
        },
    },
    security=[
        {
            "AuthToken": []
        }
    ]
)

with application.test_request_context():
    for view_func in application.view_functions.values():
        spec.path(view=view_func)
print(spec.to_yaml())
