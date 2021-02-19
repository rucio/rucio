# -*- coding: utf-8 -*-
# Copyright 2018-2021 CERN
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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2018-2021
# - Vincent Garonne <vincent.garonne@cern.ch>, 2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018-2020
# - Cedric Serfon <cedric.serfon@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021

from json import dumps

from flask import Flask, Blueprint, Response, request, jsonify

from rucio.api.account_limit import get_rse_account_usage
from rucio.api.rse import add_rse, update_rse, list_rses, del_rse, add_rse_attribute, list_rse_attributes, \
    del_rse_attribute, add_protocol, get_rse_protocols, del_protocols, update_protocols, get_rse, set_rse_usage, \
    get_rse_usage, list_rse_usage_history, set_rse_limits, get_rse_limits, delete_rse_limits, parse_rse_expression, \
    add_distance, get_distance, update_distance, list_qos_policies, add_qos_policy, delete_qos_policy
from rucio.common.exception import Duplicate, AccessDenied, RSENotFound, RSEOperationNotSupported, \
    RSEProtocolNotSupported, InvalidObject, RSEProtocolDomainNotSupported, RSEProtocolPriorityError, \
    InvalidRSEExpression, RSEAttributeNotFound, CounterNotFound, InvalidPath, ReplicaNotFound
from rucio.common.utils import render_json, APIEncoder
from rucio.rse import rsemanager
from rucio.web.rest.flaskapi.v1.common import request_auth_env, response_headers, check_accept_header_wrapper_flask, \
    try_stream, generate_http_error_flask, ErrorHandlingMethodView, json_parameters, param_get


class RSEs(ErrorHandlingMethodView):
    """ List all RSEs in the database. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self):
        """ List all RSEs.

        .. :quickref: RSEs; List all RSEs.

        :query expression: The returned list only contains RSE matching this expression.
        :resheader Content-Type: application/x-json-stream
        :status 200: DIDs found.
        :status 400: Invalid RSE Expression.
        :status 401: Invalid Auth Token.
        :status 406: Not Acceptable.
        :returns: A list containing all RSEs.
        """
        expression = request.args.get('expression', default=None)

        if expression:
            try:
                def generate(vo):
                    for rse in parse_rse_expression(expression, vo=vo):
                        yield render_json(rse=rse) + '\n'

                return try_stream(generate(vo=request.environ.get('vo')))
            except (InvalidRSEExpression, InvalidObject) as error:
                return generate_http_error_flask(400, error)
        else:
            def generate(vo):
                for rse in list_rses(vo=vo):
                    yield render_json(**rse) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))


class RSE(ErrorHandlingMethodView):
    """ Create, update, get and disable RSE. """

    def post(self, rse):
        """ Create RSE with given name.

        .. :quickref: RSE; create a new RSE.

        :param rse: The RSE name.
        :<json bool deterministic: Boolean to know if the pfn is generated deterministically.
        :<json bool volatile: Boolean for RSE cache.
        :<json string city: City for the RSE.
        :<json bool staging_area: Staging area.
        :<json string region_code: The region code for the RSE.
        :<json string country_name: The country.
        :<json string continent: The continent.
        :<json string time_zone: Timezone.
        :<json string ISP: Internet Service Provider.
        :<json string rse_type: RSE type.
        :<json number latitude: Latitude coordinate of RSE.
        :<json number longitude: Longitude coordinate of RSE.
        :<json string ASN: Access service network.
        :<json integer availability: Availability.
        :status 201: RSE created successfully.
        :status 400: Cannot decode json parameter dictionary.
        :status 401: Invalid Auth Token.
        :status 409: RSE already exists.
        :status 409: RSE not found.
        """
        kwargs = {
            'deterministic': True,
            'volatile': False,
            'city': None,
            'staging_area': False,
            'region_code': None,
            'country_name': None,
            'continent': None,
            'time_zone': None,
            'ISP': None,
            'rse_type': None,
            'latitude': None,
            'longitude': None,
            'ASN': None,
            'availability': None,
        }
        if request.get_data(as_text=True):
            parameters = json_parameters()
            for keyword in kwargs.keys():
                kwargs[keyword] = param_get(parameters, keyword, default=kwargs[keyword])
        kwargs['issuer'] = request.environ.get('issuer')
        kwargs['vo'] = request.environ.get('vo')
        try:
            add_rse(rse, **kwargs)
        except InvalidObject as error:
            return generate_http_error_flask(400, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except RSENotFound as error:
            return generate_http_error_flask(404, error)
        except Duplicate as error:
            return generate_http_error_flask(409, error)

        return 'Created', 201

    def put(self, rse):
        """ Update RSE properties (e.g. name, availability).

        .. :quickref: RSE; Update an RSE.

        :param rse: The RSE name.
        :<json dict parameters: Dictionary of parameters to update.
        :status 201: RSE updated successfully.
        :status 400: Cannot decode json parameter dictionary.
        :status 401: Invalid Auth Token.
        :status 409: RSE not found.
        :status 409: RSE already exists.

        """
        kwargs = {
            'parameters': json_parameters(optional=True),
            'issuer': request.environ.get('issuer'),
            'vo': request.environ.get('vo'),
        }
        try:
            update_rse(rse, **kwargs)
        except InvalidObject as error:
            return generate_http_error_flask(400, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except RSENotFound as error:
            return generate_http_error_flask(404, error)
        except Duplicate as error:
            return generate_http_error_flask(409, error)

        return 'Created', 201

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, rse):
        """ Details about a specific RSE.

        .. :quickref: RSE; get RSE details.

        :param rse: the RSE name.
        :resheader Content-Type: application/json
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 404: RSE not found.
        :status 406: Not Acceptable.
        :returns: A list containing all RSEs.

        """
        try:
            rse_prop = get_rse(rse=rse, vo=request.environ.get('vo'))
            return Response(render_json(**rse_prop), content_type="application/json")
        except RSENotFound as error:
            return generate_http_error_flask(404, error)

    def delete(self, rse):
        """ Disable RSE with given RSE name.

        .. :quickref: RSE; disable RSE.

        :param rse: the RSE name.
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 404: RSE not found.
        """
        try:
            del_rse(rse=rse, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except (RSENotFound, RSEOperationNotSupported, CounterNotFound) as error:
            return generate_http_error_flask(404, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)

        return '', 200


class Attributes(ErrorHandlingMethodView):
    """ Create, update, get and disable RSE attribute."""

    def post(self, rse, key):
        """ create RSE attribute with given RSE name.

        .. :quickref: Attributes; Create RSE attribute.

        :param rse: RSE name.
        :param key: Key attribute.
        :<json dict parameter: Dictionary with 'value'.
        :status 201: Created.
        :status 400: Cannot decode json parameter dictionary.
        :status 400: Key not defined.
        :status 401: Invalid Auth Token.
        :status 409: Attribute already exists.
        """
        parameters = json_parameters()
        value = param_get(parameters, 'value')
        try:
            add_rse_attribute(rse=rse, key=key, value=value, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except Duplicate as error:
            return generate_http_error_flask(409, error)
        except RSENotFound as error:
            return generate_http_error_flask(404, error)

        return 'Created', 201

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, rse):
        """
        list all RSE attributes for a RSE.

        .. :quickref: Attributes; List all RSE attributes.

        :param rse: RSE name.
        :resheader Content-Type: application/json
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 406: Not Acceptable.
        :returns: A list containing all RSE attributes.
        """
        try:
            rse_attr = list_rse_attributes(rse, vo=request.environ.get('vo'))
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except RSENotFound as error:
            return generate_http_error_flask(404, error)

        return jsonify(rse_attr)

    def delete(self, rse, key):
        """ Delete an RSE attribute for given RSE name.

        .. :quickref: Attributes; Delete RSE attribute.
        :param rse: RSE name.
        :param key: The key name.
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 404: RSE not found.
        :status 404: RSE attribute not found.

        """
        try:
            del_rse_attribute(rse=rse, key=key, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except (RSENotFound, RSEAttributeNotFound) as error:
            return generate_http_error_flask(404, error)

        return '', 200


class ProtocolList(ErrorHandlingMethodView):
    """ List supported protocols. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, rse):
        """ List all supported protocols of the given RSE.

        .. :quickref: Protocols; List all RSE protocols.

        :param rse: The RSE name.
        :resheader Content-Type: application/json
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 404: RSE Operation Not Supported.
        :status 404: RSE Not Found.
        :status 404: RSE Protocol Domain Not Supported.
        :status 404: RSE Protocol Not Supported.
        :status 406: Not Acceptable.
        :returns: A list containing all supported protocols and all their attributes.
        """
        try:
            p_list = get_rse_protocols(rse, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except (RSEOperationNotSupported, RSENotFound, RSEProtocolNotSupported, RSEProtocolDomainNotSupported) as error:
            return generate_http_error_flask(404, error)

        if len(p_list['protocols']):
            return jsonify(p_list['protocols'])
        else:
            return generate_http_error_flask(404, RSEProtocolNotSupported.__name__, 'No protocols found for this RSE')


class LFNS2PFNS(ErrorHandlingMethodView):
    """ Translate one-or-more LFNs to corresponding PFNs. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, rse, scheme=None):
        """
        Return PFNs for a set of LFNs.  Formatted as a JSON object where the key is a LFN and the
        value is the corresponding PFN.

        .. :quickref: Attributes; Translate LFNs to PFNs.

        :param rse: The RSE name.
        :param scheme: The protocol identifier.
        :query lfn: One or more LFN to translate.
        :query scheme: Optional argument to help with the protocol selection (e.g., http / gsiftp / srm)
        :query domain: Optional argument used to select the protocol for wan or lan use cases.
        :query operation: Optional query argument to select the protoco for read-vs-writes.
        :resheader Content-Type: application/json
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 404: RSE Not Found.
        :status 404: RSE Protocol Not Supported.
        :status 404: RSE Protocol Domain Not Supported.
        :status 406: Not Acceptable.
        :returns: A list with detailed PFN information.
        """
        lfns = request.args.getlist('lfn')
        lfns = list(map(lambda lfn: lfn.split(":", 1), lfns))
        if any(filter(lambda info: len(info) != 2, lfns)):
            invalid_lfns = ', '.join(filter(lambda info: len(info) != 2, lfns))
            return generate_http_error_flask(400, InvalidPath.__name__, 'LFN(s) in invalid format: ' + invalid_lfns)
        lfns = list(map(lambda info: {'scope': info[0], 'name': info[1]}, lfns))
        scheme = request.args.get('scheme', default=None)
        domain = request.args.get('domain', default='wan')
        operation = request.args.get('operation', default='write')

        try:
            rse_settings = get_rse_protocols(rse, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except (RSENotFound, RSEProtocolNotSupported, RSEProtocolDomainNotSupported) as error:
            return generate_http_error_flask(404, error)

        pfns = rsemanager.lfns2pfns(rse_settings, lfns, operation=operation, scheme=scheme, domain=domain)
        if not pfns:
            return generate_http_error_flask(404, ReplicaNotFound.__name__, 'No replicas found')

        return jsonify(pfns)


class Protocol(ErrorHandlingMethodView):
    """ Create, Update, Read and delete a specific protocol. """

    def post(self, rse, scheme):
        """
        Create a protocol for a given RSE.

        .. :quickref: Protocol; Create an RSE protocol.

        :param rse: The RSE name.
        :param scheme: The protocol identifier.
        :<json dict paramaters: parameter of the new protocol entry.
        :status 201: Created.
        :status 400: Cannot decode json parameter dictionary.
        :status 401: Invalid Auth Token.
        :status 404: RSE not found.
        :status 404: RSE Protocol Domain Not Supported.
        :status 409: RSE Protocol Priority Error.

        """
        parameters = json_parameters()

        # Fill defaults and check mandatory parameters
        parameters['scheme'] = scheme

        try:
            add_protocol(rse, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'), data=parameters)
        except (RSENotFound, RSEProtocolDomainNotSupported) as error:
            return generate_http_error_flask(404, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except (Duplicate, RSEProtocolPriorityError) as error:
            return generate_http_error_flask(409, error)
        except InvalidObject as error:
            return generate_http_error_flask(400, error)

        return 'Created', 201

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, rse, scheme):
        """ List all references of the provided RSE for the given protocol.

        .. :quickref: Protocol; List RSE protocol.

        :param rse: The RSE name.
        :param scheme: The protocol identifier.
        :resheader Content-Type: application/json
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 404: RSE Not Found.
        :status 404: RSE Protocol Not Supported.
        :status 404: RSE Protocol Domain Not Supported.
        :status 406: Not Acceptable.
        :returns: A list with detailed protocol information.

        """
        try:
            p_list = get_rse_protocols(rse, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except (RSENotFound, RSEProtocolNotSupported, RSEProtocolDomainNotSupported) as error:
            return generate_http_error_flask(404, error)

        return jsonify(p_list)

    def put(self, rse, scheme, hostname=None, port=None):
        """
        Updates attributes of an existing protocol entry. Because protocol identifier, hostname,
        and port are used as unique identifier they are immutable.

        .. :quickref: Protocol; Update RSE protocol.

        :param rse: The RSE name.
        :param scheme: The protocol identifier.
        :param hostname: The hostname defined for the scheme, used if more than one scheme is registered with the same identifier.
        :param port: The port registered for the hostname, ued if more than one scheme is registered with the same identifier and hostname.
        :<json dict paramaters: parameter of the new protocol entry.
        :status 201: Created.
        :status 400: Cannot decode json parameter dictionary.
        :status 401: Invalid Auth Token.
        :status 404: RSE not found.
        :status 404: RSE Protocol Not Supported.
        :status 404: RSE Protocol Domain Not Supported.
        :status 409: RSE Protocol Priority Error.

        """
        parameters = json_parameters()
        try:
            update_protocols(
                rse,
                issuer=request.environ.get('issuer'),
                vo=request.environ.get('vo'),
                scheme=scheme,
                hostname=hostname,
                port=port,
                data=parameters,
            )
        except InvalidObject as error:
            return generate_http_error_flask(400, error)
        except (RSEProtocolNotSupported, RSENotFound, RSEProtocolDomainNotSupported) as error:
            return generate_http_error_flask(404, error)
        except (RSEProtocolPriorityError, Duplicate) as error:
            return generate_http_error_flask(409, error)

        return '', 200

    def delete(self, rse, scheme, hostname=None, port=None):
        """
        Deletes a protocol entry for the provided RSE.

        .. :quickref: Protocol; Delete an RSE protocol.

        :param rse: The RSE name.
        :param scheme: The protocol identifier.
        :param hostname: The hostname defined for the scheme, used if more than one scheme is registered with the same identifier.
        :param port: The port registered for the hostname, ued if more than one scheme is registered with the same identifier and hostname.
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 404: RSE not found.
        :status 404: RSE Protocol Not Supported.

        """
        try:
            del_protocols(rse, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'), scheme=scheme, hostname=hostname, port=port)
        except (RSEProtocolNotSupported, RSENotFound) as error:
            return generate_http_error_flask(404, error)

        return '', 200


class Usage(ErrorHandlingMethodView):
    """ Update and read RSE space usage information. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, rse):
        """
        Get RSE usage information.

        .. :quickref: Usage; Get RSE usage.

        :param rse: the RSE name.
        :query source: The information source, e.g., srm.
        :query per_account: Boolean whether the usage should be also calculated per account or not.
        :resheader Content-Type: application/x-json-stream
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 404: RSE Not Found.
        :status 406: Not Acceptable.
        :returns: A list of dictionaries with the usage information.

        """
        per_account = request.args.get('per_account') == 'True'
        try:
            def generate(issuer, source, per_account, vo):
                for usage in get_rse_usage(rse, issuer=issuer, source=source, per_account=per_account, vo=vo):
                    yield render_json(**usage) + '\n'

            return try_stream(
                generate(
                    issuer=request.environ.get('issuer'),
                    source=request.args.get('source'),
                    per_account=per_account,
                    vo=request.environ.get('vo'),
                )
            )
        except RSENotFound as error:
            return generate_http_error_flask(404, error)

    def put(self, rse):
        """ Update RSE usage information.

        .. :quickref: Usage; Update RSE usage.

        :param rse: The RSE name.
        :<json dict parameter: Dictionary with 'source', 'used', 'free' values to update.
        :status 200: OK.
        :status 400: Cannot decode json parameter dictionary.
        :status 401: Invalid Auth Token.
        :status 404: RSE not found.

        """
        parameters = json_parameters()
        kwargs = {'source': None, 'used': None, 'free': None}
        for keyword in kwargs.keys():
            kwargs[keyword] = param_get(parameters, keyword, default=kwargs[keyword])

        try:
            set_rse_usage(rse=rse, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'), **kwargs)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except RSENotFound as error:
            return generate_http_error_flask(404, error)

        return '', 200


class UsageHistory(ErrorHandlingMethodView):
    """ Read RSE space usage history information. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, rse):
        """
        Get RSE usage information.

        .. :quickref: UsageHistory; Get RSE usage history.

        :param rse: the RSE name.
        :resheader Content-Type: application/x-json-stream
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 404: RSE Not Found.
        :status 406: Not Acceptable.
        :returns: Line separated list of dictionary with RSE usage information.

        """
        try:
            def generate(issuer, source, vo):
                for usage in list_rse_usage_history(rse=rse, issuer=issuer, source=source, vo=vo):
                    yield render_json(**usage) + '\n'

            return try_stream(generate(issuer=request.environ.get('issuer'), source=request.args.get('source'), vo=request.environ.get('vo')))
        except RSENotFound as error:
            return generate_http_error_flask(404, error)


class Limits(ErrorHandlingMethodView):
    """ Create, Update, Read and delete RSE limits. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, rse):
        """
        Get RSE limits.

        .. :quickref: Limits; Get RSE limits.

        :param rse: the RSE name.
        :resheader Content-Type: application/json
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 404: RSE Not Found.
        :status 406: Not Acceptable.
        :returns: List of dictionaries with RSE limits.

        """
        try:
            limits = get_rse_limits(rse=rse, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
            return Response(render_json(**limits), content_type="application/json")
        except RSENotFound as error:
            return generate_http_error_flask(404, error)

    def put(self, rse):
        """ Update RSE limits.

        .. :quickref: Limits; Update RSE limits.

        :param rse: The RSE name.
        :status 200: OK.
        :status 400: Cannot decode json parameter dictionary.
        :status 401: Invalid Auth Token.
        :status 404: RSE Not Found.
        """
        parameters = json_parameters()
        kwargs = {'name': None, 'value': None}
        for keyword in kwargs.keys():
            kwargs[keyword] = param_get(parameters, keyword, default=kwargs[keyword])

        try:
            set_rse_limits(rse=rse, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'), **kwargs)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except RSENotFound as error:
            return generate_http_error_flask(404, error)

        return '', 200

    def delete(self, rse):
        """ Update RSE limits.

        .. :quickref: Limits; Update RSE limits.

        :param rse: The RSE name.
        :status 200: OK.
        :status 400: Cannot decode json parameter dictionary.
        :status 401: Invalid Auth Token.
        :status 404: RSE Not Found.

        """
        parameters = json_parameters()
        name = param_get(parameters, 'name')

        try:
            delete_rse_limits(rse=rse, name=name, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except RSENotFound as error:
            return generate_http_error_flask(404, error)

        return '', 200


class RSEAccountUsageLimit(ErrorHandlingMethodView):
    """ Read and delete RSE limits for accounts. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, rse):
        """
        Get account usage and limit for one RSE.

        .. :quickref: RSEAccountUsageLimit; Get account usage.

        :param rse: the RSE name.
        :resheader Content-Type: application/json
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 404: RSE Not Found.
        :status 406: Not Acceptable.
        :returns: Line separated list of dict with account usage and limits.
        """
        try:
            def generate(vo):
                for usage in get_rse_account_usage(rse=rse, vo=vo):
                    yield render_json(**usage) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')), content_type='application/json')
        except RSENotFound as error:
            return generate_http_error_flask(404, error)


class Distance(ErrorHandlingMethodView):
    """ Create/Update and read distances between RSEs. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, source, destination):
        """
        Get RSE distance between source and destination.

        .. :quickref: Distance; Get RSE distance.

        :param source: the source RSE name.
        :param destination: the destination RSE name.
        :resheader Content-Type: application/json
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 406: Not Acceptable.
        :returns: List of dictionaries with RSE distances.
        """
        try:
            distance = get_distance(source=source, destination=destination, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
            return Response(dumps(distance, cls=APIEncoder), content_type="application/json")
        except RSENotFound as error:
            return generate_http_error_flask(404, error)

    def post(self, source, destination):
        """ Create distance information between source RSE and destination RSE.

        .. :quickref: Distance; Create RSE distance.

        :param source: The source RSE name.
        :param destination: The destination RSE name.
        :status 201: Created.
        :status 400: Cannot decode json parameter dictionary.
        :status 401: Invalid Auth Token.
        :status 404: RSE Not Found.
        """
        parameters = json_parameters()
        kwargs = {
            'ranking': None,
            'distance': None,
            'geoip_distance': None,
            'active': None,
            'submitted': None,
            'finished': None,
            'failed': None,
            'transfer_speed': None,
        }
        for keyword in kwargs.keys():
            kwargs[keyword] = param_get(parameters, keyword, default=kwargs[keyword])

        try:
            add_distance(
                source=source,
                destination=destination,
                issuer=request.environ.get('issuer'),
                vo=request.environ.get('vo'),
                **kwargs,
            )
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except RSENotFound as error:
            return generate_http_error_flask(404, error)
        except Duplicate as error:
            return generate_http_error_flask(409, error)

        return 'Created', 201

    def put(self, source, destination):
        """ Update distance information between source RSE and destination RSE.

        .. :quickref: Distance; Update RSE distance.

        :param source: The source RSE name.
        :param destination: The destination RSE name.
        :status 200: OK.
        :status 400: Cannot decode json parameter dictionary.
        :status 401: Invalid Auth Token.
        :status 404: RSE Not Found.
        """
        parameters = json_parameters()
        try:
            update_distance(
                source=source,
                destination=destination,
                issuer=request.environ.get('issuer'),
                vo=request.environ.get('vo'),
                parameters=parameters,
            )
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except RSENotFound as error:
            return generate_http_error_flask(404, error)

        return '', 200


class QoSPolicy(ErrorHandlingMethodView):
    """ Add/Delete/List QoS policies on an RSE. """

    @check_accept_header_wrapper_flask(['application/json'])
    def post(self, rse, policy):
        """
        Add QoS policy to RSE

        .. :quickref: QoSPolicy; Add QoS policy to RSE.

        :param rse: The RSE name.
        :param policy: The QoS policy name.
        :status 201: Created.
        :status 401: Invalid Auth Token.
        :status 404: RSE Not Found.
        """
        try:
            add_qos_policy(rse=rse, qos_policy=policy, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except RSENotFound as error:
            return generate_http_error_flask(404, error)

        return 'Created', 201

    @check_accept_header_wrapper_flask(['application/json'])
    def delete(self, rse, policy):
        """
        Delete QoS policy from RSE.

        .. :quickref: QoSPolicy; Delete QoS policy from RSE.

        :param rse: The RSE name.
        :param policy: The QoS policy name.
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 404: RSE not found.
        """
        try:
            delete_qos_policy(rse=rse, qos_policy=policy, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except RSENotFound as error:
            return generate_http_error_flask(404, error)

        return '', 200

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, rse):
        """
        List all QoS policies of an RSE.

        .. :quickref: QoSPolicy; List all QoS policies of an RSE.

        :param rse: The RSE name.
        :resheader Content-Type: application/json
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :returns: List of QoS policies
        """
        try:
            qos_policies = list_qos_policies(rse=rse, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
            return Response(dumps(qos_policies, cls=APIEncoder), content_type='application/json')
        except RSENotFound as error:
            return generate_http_error_flask(404, error)


def blueprint():
    bp = Blueprint('rses', __name__, url_prefix='/rses')

    attributes_view = Attributes.as_view('attributes')
    bp.add_url_rule('/<rse>/attr/<key>', view_func=attributes_view, methods=['post', 'delete'])
    bp.add_url_rule('/<rse>/attr/', view_func=attributes_view, methods=['get', ])
    distance_view = Distance.as_view('distance')
    bp.add_url_rule('/<source>/distances/<destination>', view_func=distance_view, methods=['get', 'post', 'put'])
    protocol_view = Protocol.as_view('protocol')
    bp.add_url_rule('/<rse>/protocols/<scheme>/<hostname>/<port>', view_func=protocol_view, methods=['delete', 'put'])
    bp.add_url_rule('/<rse>/protocols/<scheme>/<hostname>', view_func=protocol_view, methods=['delete', 'put'])
    bp.add_url_rule('/<rse>/protocols/<scheme>', view_func=protocol_view, methods=['get', 'post', 'delete', 'put'])
    protocol_list_view = ProtocolList.as_view('protocol_list')
    bp.add_url_rule('/<rse>/protocols', view_func=protocol_list_view, methods=['get', ])
    lfns2pfns_view = LFNS2PFNS.as_view('lfns2pfns')
    bp.add_url_rule('/<rse>/lfns2pfns', view_func=lfns2pfns_view, methods=['get', ])
    rse_account_usage_limit_view = RSEAccountUsageLimit.as_view('rse_account_usage_limit')
    bp.add_url_rule('/<rse>/accounts/usage', view_func=rse_account_usage_limit_view, methods=['get', ])
    usage_view = Usage.as_view('usage')
    bp.add_url_rule('/<rse>/usage', view_func=usage_view, methods=['get', 'put'])
    usage_history_view = UsageHistory.as_view('usage_history')
    bp.add_url_rule('/<rse>/usage/history', view_func=usage_history_view, methods=['get', ])
    limits_view = Limits.as_view('limits')
    bp.add_url_rule('/<rse>/limits', view_func=limits_view, methods=['get', 'put'])
    qos_policy_view = QoSPolicy.as_view('qos_policy')
    bp.add_url_rule('/<rse>/qos_policy', view_func=qos_policy_view, methods=['get', ])
    bp.add_url_rule('/<rse>/qos_policy/<policy>', view_func=qos_policy_view, methods=['post', 'delete'])
    rse_view = RSE.as_view('rse')
    bp.add_url_rule('/<rse>', view_func=rse_view, methods=['get', 'delete', 'put', 'post'])
    rses_view = RSEs.as_view('rses')
    bp.add_url_rule('/', view_func=rses_view, methods=['get', ])

    bp.before_request(request_auth_env)
    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
