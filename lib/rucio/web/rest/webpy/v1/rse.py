#!/usr/bin/env python
# Copyright 2012-2020 CERN for the benefit of the ATLAS collaboration.
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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2017
# - Thomas Beermann <thomas.beermann@cern.ch>, 2012, 2014
# - Ralph Vigne <ralph.vigne@cern.ch>, 2013-2014
# - Cedric Serfon <cedric.serfon@cern.ch>, 2014-2018
# - Martin Barisits <martin.barisits@cern.ch>, 2017-2020
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018-2020
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
#
# PY3K COMPATIBLE

from __future__ import print_function
from json import dumps, loads
from traceback import format_exc
try:
    from urlparse import parse_qs, parse_qsl
except ImportError:
    from urllib.parse import parse_qs, parse_qsl
from web import (application, ctx, data, header, Created, InternalError, OK,
                 input, loadhook)

from rucio.api.account_limit import get_rse_account_usage
from rucio.api.rse import (add_rse, update_rse, list_rses, del_rse, add_rse_attribute,
                           list_rse_attributes, del_rse_attribute,
                           add_protocol, get_rse_protocols, del_protocols,
                           update_protocols, get_rse, set_rse_usage,
                           get_rse_usage, list_rse_usage_history,
                           set_rse_limits, get_rse_limits, parse_rse_expression,
                           add_distance, get_distance, update_distance,
                           add_qos_policy, delete_qos_policy, list_qos_policies)
from rucio.common.exception import (Duplicate, AccessDenied, RSENotFound, RucioException,
                                    RSEOperationNotSupported, RSEProtocolNotSupported,
                                    InvalidObject, RSEProtocolDomainNotSupported,
                                    RSEProtocolPriorityError, InvalidRSEExpression,
                                    RSEAttributeNotFound, CounterNotFound)
from rucio.common.utils import generate_http_error, render_json, APIEncoder
from rucio.web.rest.common import rucio_loadhook, RucioController, check_accept_header_wrapper
from rucio.rse import rsemanager

URLS = (
    '/(.+)/attr/(.+)', 'Attributes',
    '/(.+)/attr/', 'Attributes',
    '/(.+)/distances/(.+)', 'Distance',  # List (GET), create (POST), Updates (PUT) distance
    '/(.+)/protocols/(.+)/(.+)/(.+)', 'Protocol',  # Updates (PUT) protocol attributes
    '/(.+)/protocols/(.+)/(.+)/(.+)', 'Protocol',  # delete (DELETE) a specific protocol
    '/(.+)/protocols/(.+)/(.+)', 'Protocol',  # delete (DELETE) all protocols with the same identifier and the same hostname
    '/(.+)/protocols/(.+)', 'Protocol',  # List (GET), create (POST), update (PUT), or delete (DELETE) a all protocols with the same identifier
    '/(.+)/protocols', 'Protocols',  # List all supported protocols (GET)
    '/(.+)/lfns2pfns', 'LFNS2PFNS',  # Translate a list of LFNs to PFNs (GET)
    '/(.+)/accounts/usage', 'RSEAccountUsageLimit',
    '/(.+)/usage', 'Usage',  # Update RSE usage information
    '/(.+)/usage/history', 'UsageHistory',  # Get RSE usage history information
    '/(.+)/limits', 'Limits',  # Update/List RSE limits
    '/(.+)/qos_policy', 'QoSPolicy',  # List QoS policies
    '/(.+)/qos_policy/(.+)', 'QoSPolicy',  # Add/Delete QoS policies
    '/(.+)', 'RSE',
    '/', 'RSEs',
)


class RSEs(RucioController):
    """ List all RSEs in the database. """

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self):
        """ List all RSEs.

        HTTP Success:
            200 OK

        HTTP Error:
            400 Bad request
            401 Unauthorized
            404 Resource not Found
            406 Not Acceptable
            500 InternalError

        :returns: A list containing all RSEs.
        """
        header('Content-Type', 'application/x-json-stream')
        params = input()
        if 'expression' in params:
            try:
                for rse in parse_rse_expression(params['expression'], vo=ctx.env.get('vo')):
                    item = {'rse': rse}
                    yield render_json(**item) + '\n'
            except InvalidRSEExpression as error:
                raise generate_http_error(400, 'InvalidRSEExpression', error.args[0])
            except InvalidObject as error:
                raise generate_http_error(400, 'InvalidObject', error.args[0])
            except RucioException as error:
                raise generate_http_error(500, error.__class__.__name__, error.args[0])
        else:
            for rse in list_rses(vo=ctx.env.get('vo')):
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
            404 Resource not Found
            409 Conflict
            500 Internal Error

        """
        json_data = data().decode()
        kwargs = {'deterministic': True,
                  'volatile': False, 'city': None, 'staging_area': False,
                  'region_code': None, 'country_name': None,
                  'continent': None, 'time_zone': None, 'ISP': None,
                  'rse_type': None, 'latitude': None, 'longitude': None,
                  'ASN': None, 'availability': None}
        try:
            parameters = json_data and loads(json_data)
            if parameters:
                for param in kwargs:
                    if param in parameters:
                        kwargs[param] = parameters[param]
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter dictionary')
        kwargs['issuer'] = ctx.env.get('issuer')
        kwargs['vo'] = ctx.env.get('vo')
        try:
            add_rse(rse, **kwargs)
        except InvalidObject as error:
            raise generate_http_error(400, 'InvalidObject', error.args[0])
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except Duplicate as error:
            raise generate_http_error(409, 'Duplicate', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(error)
            print(format_exc())
            raise InternalError(error)

        raise Created()

    def PUT(self, rse):
        """ Update RSE properties (e.g. name, availability).

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
        kwargs = {}

        try:
            parameters = json_data and loads(json_data)
            kwargs['parameters'] = parameters
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter dictionary')
        kwargs['issuer'] = ctx.env.get('issuer')
        kwargs['vo'] = ctx.env.get('vo')
        try:
            update_rse(rse, **kwargs)
        except InvalidObject as error:
            raise generate_http_error(400, 'InvalidObject', error.args[0])
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except Duplicate as error:
            raise generate_http_error(409, 'Duplicate', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(error)
            print(format_exc())
            raise InternalError(error)

        raise Created()

    @check_accept_header_wrapper(['application/json'])
    def GET(self, rse):
        """ Details about a specific RSE.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Resource not Found
            406 Not Acceptable
            500 InternalError

        :returns: A list containing all RSEs.
        """
        header('Content-Type', 'application/json')
        try:
            rse_prop = get_rse(rse=rse, vo=ctx.env.get('vo'))
            return render_json(**rse_prop)
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])

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
            del_rse(rse=rse, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except RSEOperationNotSupported as error:
            raise generate_http_error(404, 'RSEOperationNotSupported', error.args[0])
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except CounterNotFound as error:
            raise generate_http_error(404, 'CounterNotFound', error.args[0])

        raise OK()


class Attributes(RucioController):
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
        json_data = data().decode()
        try:
            parameter = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter dictionary')

        try:
            value = parameter['value']
        except KeyError as error:
            raise generate_http_error(400, 'KeyError', '%s not defined' % str(error))

        try:
            add_rse_attribute(rse=rse, key=key, value=value, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except Duplicate as error:
            raise generate_http_error(409, 'Duplicate', error.args[0])
        except Exception as error:
            raise InternalError(error)

        raise Created()

    @check_accept_header_wrapper(['application/json'])
    def GET(self, rse):
        """ list all RSE attributes for a RSE.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found
            406 Not Acceptable
            500 InternalError

        :param rse: RSE name.

        :returns: A list containing all RSE attributes.
        """
        header('Content-Type', 'application/json')
        try:
            rse_attr = list_rse_attributes(rse, vo=ctx.env.get('vo'))
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

        return dumps(rse_attr)

    def DELETE(self, rse, key):
        """ delete RSE attribute
         HTTP Success:
            200 OK
         HTTP Error:
            401 Unauthorized
            404 Not Found
            500 InternalError
        """
        try:
            del_rse_attribute(rse=rse, key=key, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except RSEAttributeNotFound as error:
            raise generate_http_error(404, 'RSEAttributeNotFound', error.args[0])
        except Exception as error:
            raise InternalError(error)

        raise OK()


class Protocols(RucioController):
    """ List supported protocols. """

    @check_accept_header_wrapper(['application/json'])
    def GET(self, rse):
        """ List all supported protocols of the given RSE.

        HTTP Success:
            200 OK

        HTTP Error:
            404 Resource not Found
            406 Not Acceptable
            500 InternalError

        :returns: A list containing all supported protocols and all their attributes.
        """
        header('Content-Type', 'application/json')
        p_list = None
        try:
            p_list = get_rse_protocols(rse, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
        except RSEOperationNotSupported as error:
            raise generate_http_error(404, 'RSEOperationNotSupported', error.args[0])
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except RSEProtocolNotSupported as error:
            raise generate_http_error(404, 'RSEProtocolNotSupported', error.args[0])
        except RSEProtocolDomainNotSupported as error:
            raise generate_http_error(404, 'RSEProtocolDomainNotSupported', error.args[0])
        except Exception as error:
            print(error)
            print(format_exc())
            raise InternalError(error)
        if len(p_list['protocols']):
            return dumps(p_list['protocols'])
        else:
            raise generate_http_error(404, 'RSEProtocolNotSupported', 'No prptocols found for this RSE')


class LFNS2PFNS(RucioController):
    """ Translate one-or-more LFNs to corresponding PFNs. """

    @check_accept_header_wrapper(['application/json'])
    def GET(self, rse, scheme=None):
        """
        Return PFNs for a set of LFNs.  Formatted as a JSON object where the key is a LFN and the
        value is the corresponding PFN.

        - One or more LFN should be passed as the LFN arguments.
        - A URL scheme (e.g., http / gsiftp / srm) can be passed to help with protocol selection using the
          `scheme` query argument.
        - The `domain` query argument is used to select protocol for wan or lan use cases.
        - The `operation` query argument is used to select the protocol for read-vs-writes.

        The `scheme`, `domain`, and `operation` options help with the selection of the protocol, in case
        if that affects the possible PFN generation.

        HTTP Success:
            200 OK

        HTTP Error:
            400 LFN parameter(s) malformed
            404 Resource not Found
            406 Not Acceptable
            500 InternalError

        :returns: A list with detailed PFN information.
        """
        header('Content-Type', 'application/json')

        lfns = []
        scheme = None
        domain = 'wan'
        operation = 'write'
        if ctx.query:
            params = parse_qsl(ctx.query[1:])
            for key, val in params:
                if key == 'lfn':
                    info = val.split(":", 1)
                    if len(info) != 2:
                        raise generate_http_error(400, 'InvalidPath', 'LFN in invalid format')
                    lfn_dict = {'scope': info[0], 'name': info[1]}
                    lfns.append(lfn_dict)
                elif key == 'scheme':
                    scheme = val
                elif key == 'domain':
                    domain = val
                elif key == 'operation':
                    operation = val

        rse_settings = None
        try:
            rse_settings = get_rse_protocols(rse, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except RSEProtocolNotSupported as error:
            raise generate_http_error(404, 'RSEProtocolNotSupported', error.args[0])
        except RSEProtocolDomainNotSupported as error:
            raise generate_http_error(404, 'RSEProtocolDomainNotSupported', error.args[0])
        except Exception as error:
            print(error)
            print(format_exc())
            raise InternalError(error)

        pfns = rsemanager.lfns2pfns(rse_settings, lfns, operation=operation, scheme=scheme, domain=domain)
        return dumps(pfns)


class Protocol(RucioController):
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
        json_data = data().decode()
        try:
            parameters = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter dictionary')

        # Fill defaults and check mandatory parameters
        parameters['scheme'] = scheme

        try:
            add_protocol(rse, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'), data=parameters)
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except Duplicate as error:
            raise generate_http_error(409, 'Duplicate', error.args[0])
        except InvalidObject as error:
            raise generate_http_error(400, 'InvalidObject', error.args[0])
        except RSEProtocolDomainNotSupported as error:
            raise generate_http_error(404, 'RSEProtocolDomainNotSupported', error.args[0])
        except RSEProtocolPriorityError as error:
            raise generate_http_error(409, 'RSEProtocolPriorityError', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(error)
            print(format_exc())
            raise InternalError(error)
        raise Created()

    @check_accept_header_wrapper(['application/json'])
    def GET(self, rse, scheme):
        """ List all references of the provided RSE for the given protocol.

        HTTP Success:
            200 OK

        HTTP Error:
            404 Resource not Found
            406 Not Acceptable
            500 InternalError

        :returns: A list with detailed protocol information.
        """
        header('Content-Type', 'application/json')
        p_list = None
        try:
            p_list = get_rse_protocols(rse, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except RSEProtocolNotSupported as error:
            raise generate_http_error(404, 'RSEProtocolNotSupported', error.args[0])
        except RSEProtocolDomainNotSupported as error:
            raise generate_http_error(404, 'RSEProtocolDomainNotSupported', error.args[0])
        except Exception as error:
            print(error)
            print(format_exc())
            raise InternalError(error)
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
        json_data = data().decode()
        try:
            parameter = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter dictionary')

        try:
            update_protocols(rse, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'), scheme=scheme, hostname=hostname, port=port, data=parameter)
        except InvalidObject as error:
            raise generate_http_error(400, 'InvalidObject', error.args[0])
        except RSEProtocolNotSupported as error:
            raise generate_http_error(404, 'RSEProtocolNotSupported', error.args[0])
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except RSEProtocolDomainNotSupported as error:
            raise generate_http_error(404, 'RSEProtocolDomainNotSupported', error.args[0])
        except RSEProtocolPriorityError as error:
            raise generate_http_error(409, 'RSEProtocolPriorityError', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(error)
            print(format_exc())
            raise InternalError(error)

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
            del_protocols(rse, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'), scheme=scheme, hostname=hostname, port=port)
        except RSEProtocolNotSupported as error:
            raise generate_http_error(404, 'RSEProtocolNotSupported', error.args[0])
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(error)
            print(format_exc())
            raise InternalError(error)

        raise OK()


class Usage(RucioController):
    """ Update and read RSE space usage information. """

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self, rse):
        """
        Get RSE usage information.

        :param rse: the RSE name.
        """
        header('Content-Type', 'application/x-json-stream')
        usage = None
        source = None
        per_account = False
        if ctx.query:
            params = parse_qs(ctx.query[1:])
            if 'source' in params:
                source = params['source'][0]
            if 'per_account' in params:
                per_account = params['per_account'][0] == 'True'

        try:
            usage = get_rse_usage(rse, issuer=ctx.env.get('issuer'), source=source, per_account=per_account, vo=ctx.env.get('vo'))
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

        for u in usage:
            yield render_json(**u) + '\n'

    def PUT(self, rse):
        """ Update RSE usage information.

        HTTP Success:
            200 Updated

        HTTP Error:
            400 Bad Request
            401 Unauthorized
            404 Not Found
            409 Conflict
            500 Internal Error

        :param rse: The RSE name.
        """
        json_data = data().decode()
        try:
            parameter = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter dictionary')

        try:
            set_rse_usage(rse=rse, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'), **parameter)
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

        raise OK()


class UsageHistory(RucioController):
    """ Read RSE space usage history information. """

    @check_accept_header_wrapper(['application/x-json-stream'])
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
            for usage in list_rse_usage_history(rse=rse, issuer=ctx.env.get('issuer'), source=source, vo=ctx.env.get('vo')):
                yield render_json(**usage) + '\n'
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)


class Limits(RucioController):
    """ Create, Update, Read and delete RSE limits. """

    @check_accept_header_wrapper(['application/json'])
    def GET(self, rse):
        """
        Get RSE limits.

        :param rse: the RSE name.
        """
        header('Content-Type', 'application/json')
        try:
            limits = get_rse_limits(rse=rse, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
            return render_json(**limits)
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

    def PUT(self, rse):
        """ Update RSE limits.

        HTTP Success:
            200 Updated

        HTTP Error:
            400 Bad Request
            401 Unauthorized
            404 Not Found
            409 Conflict
            500 Internal Error

        :param rse: The RSE name.
        """
        header('Content-Type', 'application/json')
        json_data = data().decode()
        try:
            parameter = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter dictionary')
        try:
            set_rse_limits(rse=rse, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'), **parameter)
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

        raise OK()


class RSEAccountUsageLimit(RucioController):
    """ Read and delete RSE limits for accounts. """

    @check_accept_header_wrapper(['application/json'])
    def GET(self, rse):
        """
        Get account usage and limit for one RSE.

        :param rse: the RSE name.
        """
        header('Content-Type', 'application/json')
        try:
            usage = get_rse_account_usage(rse=rse, vo=ctx.env.get('vo'))
            for row in usage:
                yield dumps(row, cls=APIEncoder) + '\n'
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)


class Distance(RucioController):
    """ Create/Update and read distances between RSEs. """

    @check_accept_header_wrapper(['application/json'])
    def GET(self, source, destination):
        """
        Get RSE distance between source and destination.

        :param rse: the RSE name.
        """
        header('Content-Type', 'application/json')
        try:
            distance = get_distance(source=source,
                                    destination=destination,
                                    issuer=ctx.env.get('issuer'),
                                    vo=ctx.env.get('vo'))
            return dumps(distance, cls=APIEncoder)
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

    def POST(self, source, destination):
        """ Create distance information between source RSE and destination RSE.

        HTTP Success:
            200 Updated

        HTTP Error:
            400 Bad Request
            401 Unauthorized
            404 Not Found
            409 Conflict
            500 Internal Error

        :param rse: The RSE name.
        """
        header('Content-Type', 'application/json')
        json_data = data().decode()
        try:
            parameter = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter dictionary')
        try:
            add_distance(source=source,
                         destination=destination,
                         issuer=ctx.env.get('issuer'),
                         vo=ctx.env.get('vo'),
                         **parameter)
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)
        raise Created()

    def PUT(self, source, destination):
        """ Update distance information between source RSE and destination RSE.

        HTTP Success:
            200 Updated

        HTTP Error:
            400 Bad Request
            401 Unauthorized
            404 Not Found
            409 Conflict
            500 Internal Error

        :param rse: The RSE name.
        """
        header('Content-Type', 'application/json')
        json_data = data().decode()
        try:
            parameters = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter dictionary')
        try:
            update_distance(source=source, destination=destination,
                            issuer=ctx.env.get('issuer'),
                            vo=ctx.env.get('vo'),
                            parameters=parameters)
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)
        raise OK()


class QoSPolicy(RucioController):
    """ Add/Delete/List QoS policies on an RSE. """

    @check_accept_header_wrapper(['application/json'])
    def POST(self, rse, qos_policy):
        """
        Add QoS policy to an RSE.

        :param rse: the RSE name.
        :param qos_policy: the QoS policy.
        """
        header('Content-Type', 'application/json')

        try:
            add_qos_policy(rse=rse, qos_policy=qos_policy, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

        raise Created()

    @check_accept_header_wrapper(['application/json'])
    def DELETE(self, rse, qos_policy):
        """
        Delete QoS policy from an RSE.

        :param rse: the RSE name.
        :param qos_policy: the QoS policy.
        """
        header('Content-Type', 'application/json')

        try:
            delete_qos_policy(rse=rse, qos_policy=qos_policy, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

        raise OK()

    @check_accept_header_wrapper(['application/json'])
    def GET(self, rse):
        """
        List all QoS policies of an RSE.

        :param rse: the RSE name.
        """
        header('Content-Type', 'application/json')

        try:
            qos_policies = list_qos_policies(rse=rse, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
            return dumps(qos_policies, cls=APIEncoder)
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)


"""----------------------
   Web service startup
----------------------"""

APP = application(URLS, globals())
APP.add_processor(loadhook(rucio_loadhook))
application = APP.wsgifunc()
