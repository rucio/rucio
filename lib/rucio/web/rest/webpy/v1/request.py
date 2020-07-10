#!/usr/bin/env python
# Copyright 2012-2018 CERN for the benefit of the ATLAS collaboration.
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
#
# Authors:
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014-2018
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
#
# PY3K COMPATIBLE

from logging import getLogger, StreamHandler, DEBUG
try:
    from urlparse import parse_qs
except ImportError:
    from urllib.parse import parse_qs

from web import application, ctx, loadhook, header

from rucio.api import request
from rucio.db.sqla.constants import RequestState
from rucio.core.rse import get_rses_with_attribute_value, get_rse_name
from rucio.common.schema import get_schema_value
from rucio.common.utils import generate_http_error, render_json
from rucio.web.rest.common import rucio_loadhook, RucioController, exception_wrapper, check_accept_header_wrapper


LOGGER = getLogger("rucio.request")
SH = StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)

URLS = ('%s/(.+)' % get_schema_value('SCOPE_NAME_REGEXP'), 'RequestGet',
        '/list', 'RequestsGet')


class RequestGet(RucioController):
    """ REST API to get requests. """

    @exception_wrapper
    @check_accept_header_wrapper(['application/json'])
    def GET(self, scope, name, rse):
        """
        List request for given DID to a destination RSE.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Request Not Found
            406 Not Acceptable
        """

        header('Content-Type', 'application/json')

        try:
            return render_json(**request.get_request_by_did(scope=scope,
                                                            name=name,
                                                            rse=rse,
                                                            issuer=ctx.env.get('issuer'),
                                                            vo=ctx.env.get('vo')))
        except:
            raise generate_http_error(404, 'RequestNotFound', 'No request found for DID %s:%s at RSE %s' % (scope,
                                                                                                            name,
                                                                                                            rse))


class RequestsGet(RucioController):
    """ REST API to get requests. """

    @exception_wrapper
    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self):
        """
        List requests for a given source and destination RSE or site.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Request Not Found
            406 Not Acceptable
        """

        header('Content-Type', 'application/x-json-stream')

        params = parse_qs(ctx.query[1:])
        src_rse = params.get('src_rse', [None])[0]
        dst_rse = params.get('dst_rse', [None])[0]
        src_site = params.get('src_site', [None])[0]
        dst_site = params.get('dst_site', [None])[0]
        request_states = params.get('request_states', [None])[0]

        if not request_states:
            raise generate_http_error(400, 'MissingParameter', 'Request state is missing')
        if src_rse and not dst_rse:
            raise generate_http_error(400, 'MissingParameter', 'Destination RSE is missing')
        elif dst_rse and not src_rse:
            raise generate_http_error(400, 'MissingParameter', 'Source RSE is missing')
        elif src_site and not dst_site:
            raise generate_http_error(400, 'MissingParameter', 'Destination site is missing')
        elif dst_site and not src_site:
            raise generate_http_error(400, 'MissingParameter', 'Source site is missing')

        try:
            states = [RequestState.from_string(state) for state in request_states.split(',')]
        except ValueError:
            raise generate_http_error(400, 'Invalid', 'Request state value is invalid')

        src_rses = []
        dst_rses = []
        if src_site:
            src_rses = get_rses_with_attribute_value(key='site', value=src_site, lookup_key='site', vo=ctx.env.get('vo'))
            if not src_rses:
                raise generate_http_error(404, 'NotFound', 'Could not resolve site name %s to RSE' % src_site)
            src_rses = [get_rse_name(rse['rse_id']) for rse in src_rses]
            dst_rses = get_rses_with_attribute_value(key='site', value=dst_site, lookup_key='site', vo=ctx.env.get('vo'))
            if not dst_rses:
                raise generate_http_error(404, 'NotFound', 'Could not resolve site name %s to RSE' % dst_site)
            dst_rses = [get_rse_name(rse['rse_id']) for rse in dst_rses]
        else:
            dst_rses = [dst_rse]
            src_rses = [src_rse]

        for result in request.list_requests(src_rses, dst_rses, states, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo')):
            del result['_sa_instance_state']
            yield render_json(**result) + '\n'


"""----------------------
   Web service startup
----------------------"""

APP = application(URLS, globals())
APP.add_processor(loadhook(rucio_loadhook))
application = APP.wsgifunc()
