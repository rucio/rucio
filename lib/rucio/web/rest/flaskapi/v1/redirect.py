#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2014-2017
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2014
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014, 2016-2017
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2018

from traceback import format_exc
from flask import Flask, Blueprint, Response, request, redirect
from flask.views import MethodView

from logging import getLogger, StreamHandler, DEBUG

from rucio.api.replica import list_replicas
from rucio.common.objectstore import connect, get_signed_urls
from rucio.common.exception import RucioException, DataIdentifierNotFound, ReplicaNotFound
from rucio.common.replica_sorter import sort_random, sort_geoip, sort_closeness, sort_ranking, sort_dynamic, site_selector
from rucio.common.utils import generate_http_error_flask
from rucio.web.rest.flaskapi.v1.common import before_request, after_request

LOGGER = getLogger("rucio.rucio")
SH = StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)


class MetaLinkRedirector(MethodView):

    def get(self, scope, name):
        """
        Metalink redirect

        .. :quickref: MetaLinkRedirector; Metalink redirect.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError
            404 Notfound

        :param scope: The scope name of the file.
        :param name: The name of the file.
        :resheader Content-Type: application/metalink4+xml'.
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 404: RSE Not Found.
        :status 404: DID Not Found.
        :status 500: Internal Error.
        :returns: Metalink file
        """

        dids = [{'scope': scope, 'name': name}]

        # set the correct client IP
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR')
        if client_ip is None:
            client_ip = request.remote_addr

        client_location = {'ip': client_ip,
                           'fqdn': None,
                           'site': None}

        schemes = request.args.get('schemes', ['http', 'https', 's3+rucio', 's3+https', 'root', 'gsiftp', 'srm', 'davs'])
        select = request.args.get('select', None)
        if 'sort' in request.args:
            select = request.args['sort']

        client_location['ip'] = request.args.get('ip', None)
        client_location['fqdn'] = request.args.get('fqdn', None)
        client_location['site'] = request.args.get('site', None)

        try:
            tmp_replicas = [rep for rep in list_replicas(dids=dids, schemes=schemes, client_location=client_location)]

            if not tmp_replicas:
                return 'no redirection possible - cannot find the DID', 404

            # first, set the appropriate content type, and stream the header
            data = '<?xml version="1.0" encoding="UTF-8"?>\n<metalink xmlns="urn:ietf:params:xml:ns:metalink">\n'

            # iteratively stream the XML per file
            for rfile in tmp_replicas:
                replicas = []
                dictreplica = {}
                for rse in rfile['rses']:
                    for replica in rfile['rses'][rse]:
                        replicas.append(replica)
                        dictreplica[replica] = rse

                # stream metadata
                data += ' <file name="' + rfile['name'] + '">\n'
                data += '  <identity>' + rfile['scope'] + ':' + rfile['name'] + '</identity>\n'

                if rfile['adler32'] is not None:
                    data += '  <hash type="adler32">' + rfile['adler32'] + '</hash>\n'
                if rfile['md5'] is not None:
                    data += '  <hash type="md5">' + rfile['md5'] + '</hash>\n'

                data += '  <size>' + str(rfile['bytes']) + '</size>\n'

                data += '  <glfn name="/atlas/rucio/%s:%s">' % (rfile['scope'], rfile['name'])
                data += '</glfn>\n'

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
                    data += '  <url location="' + str(dictreplica[replica]) + '" priority="' + str(idx) + '">' + replica + '</url>\n'
                    idx += 1

                data += ' </file>\n'

            # don't forget to send the metalink footer
            data += '</metalink>\n'
            return Response(data, content_type='application/metalink4+xml')
        except DataIdentifierNotFound, e:
            return generate_http_error_flask(404, 'DataIdentifierNotFound', e.args[0][0])
        except ReplicaNotFound, e:
            return generate_http_error_flask(404, 'ReplicaNotFound', e.args[0][0])
        except RucioException, e:
            return generate_http_error_flask(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            return e, 500


class HeaderRedirector(MethodView):

    def get(self, scope, name):
        """
        Header Redirect

        .. :quickref: HeaderRedirector; Header redirect.

        :param scope: The scope name of the file.
        :param name: The name of the file.
        :resheader Content-Type: application/metalink+xml'.
        :status 303: Redirect.
        :status 401: Invalid Auth Token.
        :status 404: RSE Not Found.
        :status 404: DID Not Found.
        :status 500: Internal Error.
        """

        headers = {}
        try:

            # use the default HTTP protocols if no scheme is given

            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR')
            if client_ip is None:
                client_ip = request.remote_addr

            client_location = {'ip': client_ip,
                               'fqdn': None,
                               'site': None}

            schemes = request.args.get('schemes', ['davs', 'https', 's3'])
            select = request.args.get('select', 'random')
            if 'sort' in request.args:
                select = request.args['sort']
            rse = request.args.get('rse', None)
            site = request.args.get('site', None)

            client_location['ip'] = request.args.get('ip', client_ip)
            client_location['fqdn'] = request.args.get('fqdn', None)
            client_location['site'] = request.args.get('site', None)

            # correctly forward the schemes and select to potential metalink followups
            cleaned_url = request.environ.get('REQUEST_URI').split('?')[0]
            if isinstance(schemes, list):
                headers['Link'] = '<%s/metalink?schemes=%s&select=%s>; rel=describedby; type="application/metalink+xml"' % (cleaned_url, ','.join(schemes), select)
            else:
                headers['Link'] = '<%s/metalink?schemes=%s&select=%s>; rel=describedby; type="application/metalink+xml"' % (cleaned_url, schemes, select)
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
                            return 'no redirection possible - no valid RSE for HTTP redirection found', 404
                    else:

                        for rep in r['rses']:
                            for replica in r['rses'][rep]:
                                # since this is HTTP-only redirection, and to ensure compatibility with as many http clients as possible
                                # forcibly replacement davs and s3 URLs to https
                                replica = replica.replace('davs://', 'https://').replace('s3://', 'https://')
                                dictreplica[replica] = rep

                        if not dictreplica:
                            return 'no redirection possible - no valid RSE for HTTP redirection found', 404

                        elif site:
                            rep = site_selector(dictreplica, site)
                            if rep:
                                selected_url = rep[0]
                            else:
                                return 'no redirection possible - no valid RSE for HTTP redirection found', 404
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
                    res = redirect(signed_URLS[selected_url], code=303)
                    res.header = headers
                    return res

                res = redirect(signed_URLS[selected_url], code=303)
                res.header = headers
                return res

            return 'no redirection possible - file does not exist', 404

        except ReplicaNotFound, e:
            return generate_http_error_flask(404, 'ReplicaNotFound', e.args[0][0])
        except RucioException, e:
            return generate_http_error_flask(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            return e, 500


"""----------------------
   Web service startup
----------------------"""
bp = Blueprint('redirect', __name__)

metalink_redirector_view = MetaLinkRedirector.as_view('metalink_redirector')
bp.add_url_rule('/<scope>/<name>/metalink', view_func=metalink_redirector_view, methods=['get', ])
header_redirector_view = HeaderRedirector.as_view('header_redirector')
bp.add_url_rule('/<scope>/<name>', view_func=header_redirector_view, methods=['get', ])

application = Flask(__name__)
application.register_blueprint(bp)
application.before_request(before_request)
application.after_request(after_request)


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(bp, url_prefix='/redirect')
    return doc_app


if __name__ == "__main__":
    application.run()
