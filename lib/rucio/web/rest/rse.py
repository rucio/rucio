#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012, 2014
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2013-2014
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2014-2015


from json import dumps, loads
from traceback import format_exc
from urlparse import parse_qs
from web import application, ctx, data, header, BadRequest, Created, InternalError, OK, input, loadhook

from rucio.api.account_limit import get_rse_account_usage
from rucio.api.rse import (add_rse, update_rse, list_rses, del_rse, add_rse_attribute,
                           list_rse_attributes, del_rse_attribute,
                           add_protocol, get_rse_protocols, del_protocols,
                           update_protocols, get_rse, set_rse_usage,
                           get_rse_usage, list_rse_usage_history,
                           set_rse_limits, get_rse_limits, parse_rse_expression)
from rucio.common.exception import Duplicate, AccessDenied, RSENotFound, RucioException, RSEOperationNotSupported, RSEProtocolNotSupported, InvalidObject, RSEProtocolDomainNotSupported, RSEProtocolPriorityError, InvalidRSEExpression
from rucio.common.utils import generate_http_error, render_json, APIEncoder
from rucio.web.rest.common import rucio_loadhook, RucioController

urls = (
    '/(.+)/attr/(.+)', 'Attributes',
    '/(.+)/attr/', 'Attributes',
    '/(.+)/protocols/(.+)/(.+)/(.+)', 'Protocol',  # Updates (PUT) protocol attributes
    '/(.+)/protocols/(.+)/(.+)/(.+)', 'Protocol',  # delete (DELETE) a specific protocol
    '/(.+)/protocols/(.+)/(.+)', 'Protocol',  # delete (DELETE) all protocols with the same identifier and the same hostname
    '/(.+)/protocols/(.+)', 'Protocol',  # List (GET), create (POST), update (PUT), or delete (DELETE) a all protocols with the same identifier
    '/(.+)/protocols', 'Protocols',  # List all supported protocols (GET)
    '/(.+)/accounts/usage', 'RSEAccountUsageLimit',
    '/(.+)/usage', 'Usage',  # Update RSE usage information
    '/(.+)/usage/history', 'UsageHistory',  # Get RSE usage history information
    '/(.+)/limits', 'Limits',  # Update/List RSE limits
    '/(.+)', 'RSE',
    '/', 'RSEs',
)


class RSEs(RucioController):
    """ List all RSEs in the database. """

    def GET(self):
        """ List all RSEs.

        HTTP Success:
            200 OK

        HTTP Error:
            400 Bad request
            401 Unauthorized
            404 Resource not Found
            500 InternalError

        :returns: A list containing all RSEs.
        """
        header('Content-Type', 'application/x-json-stream')
        params = input()
        if 'expression' in params:
            try:
                for rse in parse_rse_expression(params['expression']):
                    item = {'rse': rse}
                    yield render_json(**item) + '\n'
            except InvalidRSEExpression, e:
                raise generate_http_error(400, 'InvalidRSEExpression', e[0][0])
            except InvalidObject, e:
                raise generate_http_error(400, 'InvalidObject', e[0][0])
            except RucioException, e:
                raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        else:
            for rse in list_rses():
                yield render_json(**rse) + '\n'


class RSE(RucioController):
    """ Create, update, get and disable RSE. """

    def POST(self, rse):
        """ Create RSE with given name.

        HTTP Success:
            201 Created

        HTTP Error:
            400 Bad request
            401 Unauthorized
            500 Internal Error

        """
        json_data = data()
        kwargs = {'deterministic': True,
                  'volatile': False, 'city': None, 'staging_area': False,
                  'region_code': None, 'country_name': None,
                  'continent': None, 'time_zone': None, 'ISP': None}
        try:
            parameters = json_data and loads(json_data)
            if parameters:
                for param in kwargs:
                    if param in parameters:
                        kwargs[param] = parameters[param]
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter dictionary')
        kwargs['issuer'] = ctx.env.get('issuer')
        try:
            add_rse(rse, **kwargs)
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])
        except Duplicate, e:
            raise generate_http_error(409, 'Duplicate', e[0][0])
        except InvalidObject, e:
            raise generate_http_error(400, 'InvalidObject', e[0][0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print e
            print format_exc()
            raise InternalError(e)

        raise Created()

    def PUT(self, rse):
        """ Update RSE properties (e.g. name, availability).

        HTTP Success:
            201 Created

        HTTP Error:
            400 Bad request
            401 Unauthorized
            500 Internal Error

        """
        json_data = data()
        kwargs = {}

        try:
            parameters = json_data and loads(json_data)
            kwargs['parameters'] = parameters
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter dictionary')
        kwargs['issuer'] = ctx.env.get('issuer')
        try:
            update_rse(rse, **kwargs)
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])
        except Duplicate, e:
            raise generate_http_error(409, 'Duplicate', e[0][0])
        except InvalidObject, e:
            raise generate_http_error(400, 'InvalidObject', e[0][0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print e
            print format_exc()
            raise InternalError(e)

        raise Created()

    def GET(self, rse):
        """ Details about a specific RSE.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Resource not Found
            500 InternalError

        :returns: A list containing all RSEs.
        """
        header('Content-Type', 'application/json')
        try:
            rse_prop = get_rse(rse=rse)
            return render_json(**rse_prop)
        except RSENotFound, e:
            raise generate_http_error(404, 'RSENotFound', e[0][0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])

    def DELETE(self, rse):
        """ Disable RSE with given account name.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found
            500 InternalError

        :param rse: RSE name.
        """
        try:
            del_rse(rse=rse, issuer=ctx.env.get('issuer'))
        except RSENotFound, e:
            raise generate_http_error(404, 'RSENotFound', e.args[0][0])
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])

        raise OK()


class Attributes:
    """ Create, update, get and disable RSE attribute."""

    def POST(self, rse, key):
        """ create rse with given RSE name.

        HTTP Success:
            201 Created

        HTTP Error:
            400 Bad request
            401 Unauthorized
            500 Internal Error

        :param rse: RSE name.
        :param key: Key attribute.

        """
        json_data = data()
        try:
            parameter = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter dictionary')

        try:
            value = parameter['value']
        except KeyError, e:
            raise generate_http_error(400, 'KeyError', '%s not defined' % str(e))

        try:
            add_rse_attribute(rse=rse, key=key, value=value, issuer=ctx.env.get('issuer'))
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])
        except Duplicate, e:
            raise generate_http_error(409, 'Duplicate', e[0][0])
        except Exception, e:
            raise InternalError(e)

        raise Created()

    def GET(self, rse):
        """ list all RSE attributes for a RSE.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :param rse: RSE name.

        :returns: A list containing all RSE attributes.
        """
        header('Content-Type', 'application/json')
        return dumps(list_rse_attributes(rse))

    def PUT(self):
        raise BadRequest()

    def DELETE(self, rse, key):
        try:
            del_rse_attribute(rse=rse, key=key, issuer=ctx.env.get('issuer'))
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])
        except Exception, e:
            raise InternalError(e)

        raise OK()


class Protocols:
    """ List supported protocols. """

    def POST(self, rse):
        """ Not supported. """
        raise BadRequest()

    def GET(self, rse):
        """ List all supported protocols of the given RSE.

        HTTP Success:
            200 OK

        HTTP Error:
            404 Resource not Found
            500 InternalError

        :returns: A list containing all supported protocols and all their attributes.
        """
        header('Content-Type', 'application/json')
        p_list = None
        try:
            p_list = get_rse_protocols(rse, issuer=ctx.env.get('issuer'))
        except RSEOperationNotSupported, e:
            raise generate_http_error(404, 'RSEOperationNotSupported', e[0][0])
        except RSENotFound, e:
            raise generate_http_error(404, 'RSENotFound', e[0][0])
        except RSEProtocolNotSupported, e:
            raise generate_http_error(404, 'RSEProtocolNotSupported', e[0][0])
        except RSEProtocolDomainNotSupported, e:
            raise generate_http_error(404, 'RSEProtocolDomainNotSupported', e[0][0])
        except Exception, e:
            print e
            print format_exc()
            raise InternalError(e)
        if len(p_list['protocols']):
            return dumps(p_list['protocols'])
        else:
            raise generate_http_error(404, 'RSEProtocolNotSupported', 'No prptocols found for this RSE')

    def PUT(self, rse):
        """ Not supported. """
        raise BadRequest()

    def DELETE(self, rse):
        """ Not supported. """
        raise BadRequest()


class Protocol:
    """ Create, Update, Read and delete a specific protocol. """

    def POST(self, rse, scheme):
        """
        Create a protocol for a given RSE.

        HTTP Success:
            201 Created

        HTTP Error:
            400 Bad request
            401 Unauthorized
            404 Resource not Found
            409 Conflict
            500 Internal Error

        """
        json_data = data()
        try:
            parameters = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter dictionary')

        # Fill defaults and check mandatory parameters
        parameters['scheme'] = scheme

        try:
            add_protocol(rse, issuer=ctx.env.get('issuer'), data=parameters)
        except RSENotFound, e:
            raise generate_http_error(404, 'RSENotFound', e[0][0])
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])
        except Duplicate, e:
            raise generate_http_error(409, 'Duplicate', e[0][0])
        except InvalidObject, e:
            raise generate_http_error(400, 'InvalidObject', e[0][0])
        except RSEProtocolDomainNotSupported, e:
            raise generate_http_error(404, 'RSEProtocolDomainNotSupported', e[0][0])
        except RSEProtocolPriorityError, e:
            raise generate_http_error(409, 'RSEProtocolPriorityError', e[0][0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print e
            print format_exc()
            raise InternalError(e)
        raise Created()

    def GET(self, rse, scheme):
        """ List all references of the provided RSE for the given protocol.

        HTTP Success:
            200 OK

        HTTP Error:
            404 Resource not Found
            500 InternalError

        :returns: A list with detailed protocol information.
        """
        header('Content-Type', 'application/json')
        p_list = None
        try:
            p_list = get_rse_protocols(rse, issuer=ctx.env.get('issuer'))
        except RSENotFound, e:
            raise generate_http_error(404, 'RSENotFound', e[0][0])
        except RSEProtocolNotSupported, e:
            raise generate_http_error(404, 'RSEProtocolNotSupported', e[0][0])
        except RSEProtocolDomainNotSupported, e:
            raise generate_http_error(404, 'RSEProtocolDomainNotSupported', e[0][0])
        except Exception, e:
            print e
            print format_exc()
            raise InternalError(e)
        return dumps(p_list)

    def PUT(self, rse, scheme, hostname=None, port=None):
        """
        Updates attributes of an existing protocol entry. Because protocol identifier, hostname,
        and port are used as unique identifier they are immutable.

        HTTP Success:
            200 OK

        HTTP Error:
            400 Bad Request
            401 Unauthorized
            404 Resource not Found
            409 Conflict
            500 InternalError
        """
        json_data = data()
        try:
            parameter = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter dictionary')

        try:
            update_protocols(rse, issuer=ctx.env.get('issuer'), scheme=scheme, hostname=hostname, port=port, data=parameter)
        except InvalidObject, e:
            raise generate_http_error(400, 'InvalidObject', e[0][0])
        except RSEProtocolNotSupported, e:
            raise generate_http_error(404, 'RSEProtocolNotSupported', e[0][0])
        except RSENotFound, e:
            raise generate_http_error(404, 'RSENotFound', e[0][0])
        except RSEProtocolDomainNotSupported, e:
            raise generate_http_error(404, 'RSEProtocolDomainNotSupported', e[0][0])
        except RSEProtocolPriorityError, e:
            raise generate_http_error(409, 'RSEProtocolPriorityError', e[0][0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print e
            print format_exc()
            raise InternalError(e)

        raise OK()

    def DELETE(self, rse, scheme, hostname=None, port=None):
        """
        Deletes a protocol entry for the provided RSE.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Resource not Found
            500 InternalError
        """
        try:
            del_protocols(rse, issuer=ctx.env.get('issuer'), scheme=scheme, hostname=hostname, port=port)
        except RSEProtocolNotSupported, e:
            raise generate_http_error(404, 'RSEProtocolNotSupported', e[0][0])
        except RSENotFound, e:
            raise generate_http_error(404, 'RSENotFound', e[0][0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print e
            print format_exc()
            raise InternalError(e)

        raise OK()


class Usage:

    def POST(self, rse):
        """ Not supported. """
        raise BadRequest()

    def GET(self, rse):
        """
        Get RSE usage information.

        :param rse: the RSE name.
        """
        header('Content-Type', 'application/x-json-stream')
        usage = None
        source = None
        if ctx.query:
            params = parse_qs(ctx.query[1:])
            if 'source' in params:
                source = params['source'][0]

        try:
            usage = get_rse_usage(rse, issuer=ctx.env.get('issuer'), source=source)
        except RSENotFound, e:
            raise generate_http_error(404, 'RSENotFound', e[0][0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            raise InternalError(e)

        for u in usage:
            yield render_json(**u) + '\n'

    def PUT(self, rse):
        """ Update RSE usage information.

        HTTP Success:
            200 Updated

        HTTP Error:
            400 Bad Request
            401 Unauthorized
            409 Conflict
            500 Internal Error

        :param rse: The RSE name.
        """
        json_data = data()
        try:
            parameter = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter dictionary')

        try:
            set_rse_usage(rse=rse, issuer=ctx.env.get('issuer'), **parameter)
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            raise InternalError(e)

        raise OK()

    def DELETE(self, rse):
        """ Not supported. """
        raise BadRequest()


class UsageHistory:

    def POST(self, rse):
        """ Not supported. """
        raise BadRequest()

    def GET(self, rse):
        """
        Get RSE usage information.

        :param rse: the RSE name.
        """
        header('Content-Type', 'application/x-json-stream')
        source = None
        if ctx.query:
            params = parse_qs(ctx.query[1:])
            if 'source' in params:
                source = params['source'][0]

        try:
            for usage in list_rse_usage_history(rse=rse, issuer=ctx.env.get('issuer'), source=source):
                yield render_json(**usage) + '\n'
        except RSENotFound, e:
            raise generate_http_error(404, 'RSENotFound', e[0][0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            raise InternalError(e)

    def PUT(self, rse):
        """ Not supported. """
        raise BadRequest()

    def DELETE(self, rse):
        """ Not supported. """
        raise BadRequest()


class Limits:

    def POST(self, rse):
        """ Not supported. """
        raise BadRequest()

    def GET(self, rse):
        """
        Get RSE limits.

        :param rse: the RSE name.
        """
        header('Content-Type', 'application/json')
        try:
            limits = get_rse_limits(rse=rse, issuer=ctx.env.get('issuer'))
            return render_json(**limits)
        except RSENotFound, e:
            raise generate_http_error(404, 'RSENotFound', e[0][0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            raise InternalError(e)

    def PUT(self, rse):
        """ Update RSE limits.

        HTTP Success:
            200 Updated

        HTTP Error:
            400 Bad Request
            401 Unauthorized
            409 Conflict
            500 Internal Error

        :param rse: The RSE name.
        """
        header('Content-Type', 'application/json')
        json_data = data()
        try:
            parameter = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter dictionary')
        try:
            set_rse_limits(rse=rse, issuer=ctx.env.get('issuer'), **parameter)
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            raise InternalError(e)

        raise OK()

    def DELETE(self, rse):
        """ Not supported. """
        raise BadRequest()


class RSEAccountUsageLimit:

    def GET(self, rse):
        """
        Get account usage and limit for one RSE.

        :param rse: the RSE name.
        """
        header('Content-Type', 'application/json')
        try:
            usage = get_rse_account_usage(rse=rse)
            for row in usage:
                yield dumps(row, cls=APIEncoder) + '\n'
        except RSENotFound, e:
            raise generate_http_error(404, 'RSENotFound', e[0][0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            raise InternalError(e)


"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
app.add_processor(loadhook(rucio_loadhook))
application = app.wsgifunc()
