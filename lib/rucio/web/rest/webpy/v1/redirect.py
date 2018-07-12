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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2014-2017
# - Cedric Serfon <cedric.serfon@cern.ch>, 2014
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014-2018

from traceback import format_exc
from urlparse import parse_qs
from web import application, ctx, header, seeother, InternalError

from logging import getLogger, StreamHandler, DEBUG

from rucio.api.replica import list_replicas
from rucio.common.objectstore import connect, get_signed_urls
from rucio.common.exception import RucioException, DataIdentifierNotFound, ReplicaNotFound
from rucio.common.replica_sorter import sort_random, sort_geoip, sort_closeness, sort_ranking, sort_dynamic, site_selector
from rucio.common.schema import SCOPE_NAME_REGEXP
from rucio.common.utils import generate_http_error
from rucio.web.rest.common import RucioController


LOGGER = getLogger("rucio.rucio")
SH = StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)

URLS = ('%s/metalink?$' % SCOPE_NAME_REGEXP, 'MetaLinkRedirector',
        '%s/?$' % SCOPE_NAME_REGEXP, 'HeaderRedirector')


class MetaLinkRedirector(RucioController):

    def GET(self, scope, name):
        """
        Metalink redirect

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError
            404 Notfound

        :param scope: The scope name of the file.
        :param name: The name of the file.
        """

        header('Access-Control-Allow-Origin', ctx.env.get('HTTP_ORIGIN'))
        header('Access-Control-Allow-Headers', ctx.env.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        header('Access-Control-Allow-Methods', '*')
        header('Access-Control-Allow-Credentials', 'true')

        dids, schemes, select = [{'scope': scope, 'name': name}], ['http', 'https', 's3+rucio', 's3+https', 'root', 'gsiftp', 'srm', 'davs'], None

        # set the correct client IP
        client_ip = ctx.env.get('HTTP_X_FORWARDED_FOR')
        if client_ip is None:
            client_ip = ctx.ip

        client_location = {'ip': client_ip,
                           'fqdn': None,
                           'site': None}

        if ctx.query:
            params = parse_qs(ctx.query[1:])
            if 'schemes' in params:
                schemes = params['schemes']
            if 'select' in params:
                select = params['select'][0]
            if 'sort' in params:
                select = params['sort'][0]

            if 'ip' in params:
                client_location['ip'] = params['ip'][0]
            if 'fqdn' in params:
                client_location['fqdn'] = params['fqdn'][0]
            if 'site' in params:
                client_location['site'] = params['site'][0]

        try:
            tmp_replicas = [rep for rep in list_replicas(dids=dids, schemes=schemes, client_location=client_location)]

            if not tmp_replicas:
                raise ReplicaNotFound('no redirection possible - cannot find the DID')

            # first, set the appropriate content type, and stream the header
            header('Content-Type', 'application/metalink4+xml')
            yield '<?xml version="1.0" encoding="UTF-8"?>\n<metalink xmlns="urn:ietf:params:xml:ns:metalink">\n'

            # iteratively stream the XML per file
            for rfile in tmp_replicas:
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

                # sort the actual replicas if necessary
                if select == 'geoip':
                    replicas = sort_geoip(dictreplica, client_location['ip'])
                elif select == 'closeness':
                    replicas = sort_closeness(dictreplica, client_location)
                elif select == 'dynamic':
                    replicas = sort_dynamic(dictreplica, client_location)
                elif select == 'ranking':
                    replicas = sort_ranking(dictreplica, client_location)
                else:
                    replicas = sort_random(dictreplica)

                # stream URLs
                idx = 1
                for replica in replicas:
                    yield '  <url location="' + str(dictreplica[replica]) + '" priority="' + str(idx) + '">' + replica + '</url>\n'
                    idx += 1

                yield ' </file>\n'

            # don't forget to send the metalink footer
            yield '</metalink>\n'

        except DataIdentifierNotFound as error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0])
        except ReplicaNotFound as error:
            raise generate_http_error(404, 'ReplicaNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print format_exc()
            raise InternalError(error)


class HeaderRedirector(RucioController):

    def GET(self, scope, name):
        """
        Header Redirect

        HTTP Success:
            303 See Other

        HTTP Error:
            401 Unauthorized
            500 InternalError
            404 Notfound

        :param scope: The scope name of the file.
        :param name: The name of the file.
        """

        header('Access-Control-Allow-Origin', ctx.env.get('HTTP_ORIGIN'))
        header('Access-Control-Allow-Headers', ctx.env.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        header('Access-Control-Allow-Methods', '*')
        header('Access-Control-Allow-Credentials', 'true')

        try:

            # use the default HTTP protocols if no scheme is given
            select, rse, site, schemes = 'random', None, None, ['davs', 'http', 'https', 's3+rucio']

            client_ip = ctx.env.get('HTTP_X_FORWARDED_FOR')
            if client_ip is None:
                client_ip = ctx.ip

            client_location = {'ip': client_ip,
                               'fqdn': None,
                               'site': None}

            if ctx.query:
                params = parse_qs(ctx.query[1:])
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
            cleaned_url = ctx.env.get('REQUEST_URI').split('?')[0]
            if isinstance(schemes, list):
                header('Link', '<%s/metalink?schemes=%s&select=%s>; rel=describedby; type="application/metalink+xml"' % (cleaned_url, ','.join(schemes), select))
            else:
                header('Link', '<%s/metalink?schemes=%s&select=%s>; rel=describedby; type="application/metalink+xml"' % (cleaned_url, schemes, select))
                schemes = [schemes]  # list_replicas needs a list

            replicas = [r for r in list_replicas(dids=[{'scope': scope, 'name': name, 'type': 'FILE'}], schemes=schemes, client_location=client_location)]

            selected_url, selected_rse = None, None
            for r in replicas:
                if r['rses']:
                    dictreplica = {}

                    if rse:
                        if rse in r['rses'] and r['rses'][rse]:
                            selected_url = r['rses'][rse][0]
                            selected_rse = rse
                        else:
                            raise ReplicaNotFound('no redirection possible - no valid RSE for HTTP redirection found')
                    else:

                        for rep in r['rses']:
                            for replica in r['rses'][rep]:
                                # since this is HTTP-only redirection, and to ensure compatibility with as many http clients as possible
                                # forcibly replacement davs and s3 URLs to https
                                replica = replica.replace('davs://', 'https://').replace('s3://', 'https://')
                                dictreplica[replica] = rep

                        if not dictreplica:
                            raise ReplicaNotFound('no redirection possible - no valid RSE for HTTP redirection found')

                        elif site:
                            rep = site_selector(dictreplica, site)
                            if rep:
                                selected_url = rep[0]
                            else:
                                raise ReplicaNotFound('no redirection possible - no valid RSE for HTTP redirection found')
                        else:
                            if select == 'geoip':
                                rep = sort_geoip(dictreplica, client_location['ip'])
                            elif select == 'closeness':
                                rep = sort_closeness(dictreplica, client_location)
                            elif select == 'dynamic':
                                rep = sort_dynamic(dictreplica, client_location)
                            elif select == 'ranking':
                                rep = sort_ranking(dictreplica, client_location)
                            else:
                                rep = sort_random(dictreplica)

                            selected_url = rep[0]

                        for rep in r['rses']:
                            for replica in r['rses'][rep]:
                                if selected_url == replica:
                                    selected_rse = rep

            if selected_url:
                if selected_url.startswith('s3+rucio://'):
                    connect(selected_rse, selected_url)
                    signed_URLS = get_signed_urls([selected_url],
                                                  rse=selected_rse,
                                                  operation='read')
                    raise seeother(signed_URLS[selected_url])

                raise seeother(selected_url)

            raise ReplicaNotFound('no redirection possible - file does not exist')

        except seeother:
            raise
        except ReplicaNotFound as error:
            raise generate_http_error(404, 'ReplicaNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print format_exc()
            raise InternalError(error)


"""----------------------
   Web service startup
----------------------"""

APP = application(URLS, globals())
application = APP.wsgifunc()
