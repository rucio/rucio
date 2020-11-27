# -*- coding: utf-8 -*-
# Copyright 2014-2020 CERN
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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2014-2017
# - Cedric Serfon <cedric.serfon@cern.ch>, 2014-2019
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014-2018
# - Thomas Beermann <thomas.beermann@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - James Perry <j.perry@epcc.ed.ac.uk>, 2019-2020
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
# - Martin Barisits <martin.barisits@cern.ch>, 2020

from __future__ import print_function

import itertools
from traceback import format_exc

from flask import Flask, Blueprint, request, redirect
from flask.views import MethodView
from werkzeug.datastructures import Headers

from rucio.api.replica import list_replicas
from rucio.common.exception import RucioException, DataIdentifierNotFound, ReplicaNotFound
from rucio.core.replica_sorter import site_selector, sort_replicas
from rucio.web.rest.flaskapi.v1.common import check_accept_header_wrapper_flask, parse_scope_name, try_stream
from rucio.web.rest.utils import generate_http_error_flask

try:
    from urlparse import parse_qs
except ImportError:
    from urllib.parse import parse_qs


class MetaLinkRedirector(MethodView):

    @check_accept_header_wrapper_flask(['application/metalink4+xml'])
    def get(self, scope_name):
        """
        Metalink redirect

        .. :quickref: MetaLinkRedirector; Metalink redirect.

        :param scope_name: data identifier (scope)/(name).
        :resheader Content-Type: application/metalink4+xml'.
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 404: RSE Not Found.
        :status 404: DID Not Found.
        :status 406: Not Acceptable.
        :status 500: Internal Error.
        :returns: Metalink file
        """
        headers = Headers()
        headers.set('Access-Control-Allow-Origin', request.environ.get('HTTP_ORIGIN'))
        headers.set('Access-Control-Allow-Headers', request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        headers.set('Access-Control-Allow-Methods', '*')
        headers.set('Access-Control-Allow-Credentials', 'true')

        try:
            scope, name = parse_scope_name(scope_name, request.headers.get('X-Rucio-VO', default='def'))
        except ValueError as error:
            return generate_http_error_flask(400, 'ValueError', error.args[0], headers=headers)
        except Exception as error:
            print(format_exc())
            return str(error), 500, headers

        dids, schemes, sortby = [{'scope': scope, 'name': name}], ['http', 'https', 'root', 'gsiftp', 'srm', 'davs'], None

        # set the correct client IP
        client_ip = request.headers.get('X-Forwarded-For', default=request.remote_addr)

        client_location = {'ip': client_ip,
                           'fqdn': None,
                           'site': None}

        if request.query_string:
            query_string = request.query_string.decode(encoding='utf-8')
            params = parse_qs(query_string)
            if 'schemes' in params:
                schemes = params['schemes']
            if 'select' in params:
                sortby = params['select'][0]
            if 'sort' in params:
                sortby = params['sort'][0]

            if 'ip' in params:
                client_location['ip'] = params['ip'][0]
            if 'fqdn' in params:
                client_location['fqdn'] = params['fqdn'][0]
            if 'site' in params:
                client_location['site'] = params['site'][0]

        # get vo if given
        vo = request.headers.get('X-Rucio-VO', default='def')

        try:
            replicas_iter = list_replicas(dids=dids, schemes=schemes, client_location=client_location, vo=vo)
            try:
                first = next(replicas_iter)
            except StopIteration:
                return 'no redirection possible - cannot find the DID', 404

            def generate():
                # first, set the appropriate content type, and stream the header
                yield '<?xml version="1.0" encoding="UTF-8"?>\n<metalink xmlns="urn:ietf:params:xml:ns:metalink">\n'

                # iteratively stream the XML per file
                for rfile in itertools.chain((first, ), replicas_iter):
                    replicas = []
                    dictreplica = {}
                    for rse in rfile['rses']:
                        for replica in rfile['rses'][rse]:
                            replicas.append(replica)
                            dictreplica[replica] = rse

                    # stream metadata
                    yield ' <file name="' + rfile['name'] + '">\n'
                    yield '  <identity>' + rfile['scope'] + ':' + rfile['name'] + '</identity>\n'

                    if rfile['adler32'] is not None:
                        yield '  <hash type="adler32">' + rfile['adler32'] + '</hash>\n'
                    if rfile['md5'] is not None:
                        yield '  <hash type="md5">' + rfile['md5'] + '</hash>\n'

                    yield '  <size>' + str(rfile['bytes']) + '</size>\n'

                    yield '  <glfn name="/atlas/rucio/%s:%s">' % (rfile['scope'], rfile['name'])
                    yield '</glfn>\n'

                    replicas = sort_replicas(dictreplica, client_location, selection=sortby)

                    # stream URLs
                    idx = 1
                    for replica in replicas:
                        yield '  <url location="' + str(dictreplica[replica]) + '" priority="' + str(idx) + '">' + replica + '</url>\n'
                        idx += 1

                    yield ' </file>\n'

                # don't forget to send the metalink footer
                yield '</metalink>\n'

            return try_stream(generate(), content_type='application/metalink4+xml')
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, 'DataIdentifierNotFound', error.args[0], headers=headers)
        except ReplicaNotFound as error:
            return generate_http_error_flask(404, 'ReplicaNotFound', error.args[0], headers=headers)
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0], headers=headers)
        except Exception as error:
            print(format_exc())
            return str(error), 500, headers


class HeaderRedirector(MethodView):

    def get(self, scope_name):
        """
        Header Redirect

        .. :quickref: HeaderRedirector; Header redirect.

        :param scope_name: data identifier (scope)/(name).
        :resheader Content-Type: application/metalink+xml'.
        :status 303: Redirect.
        :status 401: Invalid Auth Token.
        :status 404: RSE Not Found.
        :status 404: DID Not Found.
        :status 500: Internal Error.
        """
        headers = Headers()
        headers.set('Access-Control-Allow-Origin', request.environ.get('HTTP_ORIGIN'))
        headers.set('Access-Control-Allow-Headers', request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        headers.set('Access-Control-Allow-Methods', '*')
        headers.set('Access-Control-Allow-Credentials', 'true')

        try:
            scope, name = parse_scope_name(scope_name, request.headers.get('X-Rucio-VO', default='def'))
        except ValueError as error:
            return generate_http_error_flask(400, 'ValueError', error.args[0], headers=headers)
        except Exception as error:
            print(format_exc())
            return str(error), 500, headers

        try:

            # use the default HTTP protocols if no scheme is given
            select, rse, site, schemes = 'random', None, None, ['davs', 'http', 'https']

            client_ip = request.headers.get('X-Forwarded-For', default=request.remote_addr)

            client_location = {'ip': client_ip,
                               'fqdn': None,
                               'site': None}

            if request.query_string:
                query_string = request.query_string.decode(encoding='utf-8')
                params = parse_qs(query_string)
                if 'select' in params:
                    select = params['select'][0]
                if 'sort' in params:
                    select = params['sort'][0]
                if 'rse' in params:
                    rse = params['rse'][0]
                if 'site' in params:
                    site = params['site'][0]
                if 'schemes' in params:
                    schemes = params['schemes'][0]
                else:
                    schemes = ['davs', 'https', 's3']

                if 'ip' in params:
                    client_location['ip'] = params['ip'][0]
                if 'fqdn' in params:
                    client_location['fqdn'] = params['fqdn'][0]
                if 'site' in params:
                    client_location['site'] = params['site'][0]

            # correctly forward the schemes and select to potential metalink followups
            cleaned_url = request.environ.get('REQUEST_URI').split('?')[0]
            if isinstance(schemes, list):
                headers.set('Link', '<%s/metalink?schemes=%s&select=%s>; rel=describedby; type="application/metalink+xml"' % (cleaned_url, ','.join(schemes), select))
            else:
                headers.set('Link', '<%s/metalink?schemes=%s&select=%s>; rel=describedby; type="application/metalink+xml"' % (cleaned_url, schemes, select))
                schemes = [schemes]  # list_replicas needs a list

            # get vo if given
            vo = request.headers.get('X-Rucio-VO', default='def')

            replicas = [r for r in list_replicas(dids=[{'scope': scope, 'name': name, 'type': 'FILE'}],
                                                 schemes=schemes, client_location=client_location, vo=vo)]

            selected_url = None
            for r in replicas:
                if r['rses']:
                    dictreplica = {}

                    if rse:
                        if rse in r['rses'] and r['rses'][rse]:
                            selected_url = r['rses'][rse][0]
                        else:
                            return 'no redirection possible - no valid RSE for HTTP redirection found', 404, headers
                    else:

                        for rep in r['rses']:
                            for replica in r['rses'][rep]:
                                # since this is HTTP-only redirection, and to ensure compatibility with as many http clients as possible
                                # forcibly replacement davs and s3 URLs to https
                                replica = replica.replace('davs://', 'https://').replace('s3://', 'https://')
                                dictreplica[replica] = rep

                        if not dictreplica:
                            return 'no redirection possible - no valid RSE for HTTP redirection found', 404, headers

                        elif site:
                            rep = site_selector(dictreplica, site, vo)
                            if rep:
                                selected_url = rep[0]
                            else:
                                return 'no redirection possible - no valid RSE for HTTP redirection found', 404, headers
                        else:
                            rep = sort_replicas(dictreplica, client_location, selection=select)
                            selected_url = rep[0]

            if selected_url:
                response = redirect(selected_url, code=303)
                response.headers.extend(headers)
                return response

            return 'no redirection possible - file does not exist', 404, headers
        except ReplicaNotFound as error:
            return generate_http_error_flask(404, 'ReplicaNotFound', error.args[0], headers=headers)
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0], headers=headers)
        except Exception as error:
            print(format_exc())
            return str(error), 500, headers


def blueprint(no_doc=True):
    bp = Blueprint('redirect', __name__, url_prefix='/redirect')

    metalink_redirector_view = MetaLinkRedirector.as_view('metalink_redirector')
    bp.add_url_rule('/<path:scope_name>/metalink', view_func=metalink_redirector_view, methods=['get', ])
    header_redirector_view = HeaderRedirector.as_view('header_redirector')
    bp.add_url_rule('/<path:scope_name>', view_func=header_redirector_view, methods=['get', ])
    if no_doc:
        bp.add_url_rule('/<path:scope_name>/', view_func=header_redirector_view, methods=['get', ])

    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint(no_doc=False))
    return doc_app
