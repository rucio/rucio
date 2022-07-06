# -*- coding: utf-8 -*-
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

from json import dumps

from flask import Flask, Blueprint, Response, request, jsonify

from rucio.api.account_limit import get_rse_account_usage
from rucio.api.rse import add_rse, update_rse, list_rses, del_rse, add_rse_attribute, list_rse_attributes, \
    del_rse_attribute, add_protocol, get_rse_protocols, del_protocols, update_protocols, get_rse, set_rse_usage, \
    get_rse_usage, list_rse_usage_history, set_rse_limits, get_rse_limits, delete_rse_limits, parse_rse_expression, \
    add_distance, get_distance, update_distance, delete_distance, list_qos_policies, add_qos_policy, delete_qos_policy
from rucio.common.exception import Duplicate, AccessDenied, RSENotFound, RSEOperationNotSupported, \
    RSEProtocolNotSupported, InvalidObject, RSEProtocolDomainNotSupported, RSEProtocolPriorityError, \
    InvalidRSEExpression, RSEAttributeNotFound, CounterNotFound, InvalidPath, ReplicaNotFound, InputValidationError
from rucio.common.utils import render_json, APIEncoder
from rucio.rse import rsemanager
from rucio.web.rest.flaskapi.v1.common import request_auth_env, response_headers, check_accept_header_wrapper_flask, \
    try_stream, generate_http_error_flask, ErrorHandlingMethodView, json_parameters, param_get


class RSEs(ErrorHandlingMethodView):
    """ List all RSEs in the database. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self):
        """
        ---
        summary: List RSEs
        description: Lists all RSEs.
        tags:
          - Rucio Storage Elements
        requestBody:
          content:
            application/json:
              schema:
                type: object
                properties:
                  expression:
                    description: An RSE expression.
                    type: string
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  description: A list with the corresponding rses.
                  type: array
                  items:
                    type: object
                    properties:
                      id:
                        description: The rse id.
                        type: string
                      rse:
                        description: The name of the rse.
                        type: string
                      rse_type:
                        description: The type of the rse.
                        type: string
                      deterministic:
                        description: If the rse is deterministic.
                        type: boolean
                      volatile:
                        description: If the rse is volatile.
                        type: boolean
                      staging_area:
                        description: Is this rse a staging area?
                        type: boolean
                      city:
                        description: The city of the rse.
                        type: string
                      region_code:
                        description: The region_code of the rse.
                        type: string
                      country_name:
                        description: The country name of the rse.
                        type: string
                      continent:
                        description: The continent of the rse.
                        type: string
                      time_zone:
                        description: The time zone of the rse.
                        type: string
                      ISP:
                        description: The isp of the rse.
                        type: string
                      ASN:
                        description: The asn of the rse.
                        type: string
                      longitude:
                        description: The longitude of the rse.
                        type: number
                      latitude:
                        description: The latitude of the rse.
                        type: number
                      availability:
                        description: The availability of the rse.
                        type: integer
                      usage:
                        description: The usage of the rse.
                        type: integer
                      qos_class:
                        description: The quality of service class.
                        type: string
          400:
            description: Invalid RSE expression
          401:
            description: Invalid Auth Token
          406:
            description: Not acceptable
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
        """
        ---
        summary: Create RSE
        description: Creates a RSE with all the metadata.
        tags:
          - Rucio Storage Elements
        parameters:
        - name: rse
          in: path
          description: The name of the Rucio Storage Element name.
          schema:
            type: string
          style: simple
        requestBody:
          content:
            application/json:
              schema:
                type: object
                properties:
                  deterministic:
                    description: If the pfn is generated deterministicly.
                    type: boolean
                  volatile:
                    description: RSE cache.
                    type: boolean
                  city:
                    description: The city of the RSE.
                    type: string
                  staging_area:
                    description: Staging area.
                    type: string
                  region_code:
                    description: The region code of the RSE.
                    type: string
                  country_name:
                    description: The country name of the RSE.
                    type: string
                  continent:
                    description: The continent of the RSE.
                    type: string
                  time_zone:
                    description: The time zone of the RSE.
                    type: string
                  ISP:
                    description: The internet service provider of the RSE.
                    type: string
                  rse_type:
                    description: The rse type.
                    type: string
                    enum: ["DISK", "TAPE"]
                  latitute:
                    description: The latitute of the RSE.
                    type: float
                  longitude:
                    description: The longitude of the RSE.
                    type: float
                  ASN:
                    description: The access service network of the RSE.
                    type: string
                  availability:
                    description: The availability of the RSE.
                    type: integer
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          400:
            description: Cannot decode json parameter dictionary
          401:
            description: Invalid Auth Token
          404:
            description: RSE not found
          409:
            description: RSE already exists.
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
        """
        ---
        summary: Update RSE
        description: Update RSE properties.
        tags:
          - Rucio Storage Elements
        parameters:
        - name: rse
          in: path
          description: The name of the Rucio Storage Element name.
          schema:
            type: string
          style: simple
        requestBody:
          content:
            application/json:
              schema:
                type: object
                properties:
                  availability_raed:
                    description: The vailability of the RSE.
                    type: boolean
                  availability_write:
                    description: The vailability of the RSE.
                    type: boolean
                  availability_delete:
                    description: The vailability of the RSE.
                    type: boolean
                  deterministic:
                    description: If the pfn is generated deterministicly.
                    type: boolean
                  volatile:
                    description: RSE cache.
                    type: boolean
                  city:
                    description: The city of the RSE.
                    type: string
                  staging_area:
                    description: Staging area.
                    type: string
                  region_code:
                    description: The region code of the RSE.
                    type: string
                  country_name:
                    description: The country name of the RSE.
                    type: string
                  time_zone:
                    description: The time zone of the RSE.
                    type: string
                  rse_type:
                    description: The rse type.
                    type: string
                    enum: ["DISK", "TAPE"]
                  latitute:
                    description: The latitute of the RSE.
                    type: float
                  longitude:
                    description: The longitude of the RSE.
                    type: float
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          400:
            description: Cannot decode json parameter dictionary or invalid option provided
          401:
            description: Invalid Auth Token
          404:
            description: RSE not found
        """
        kwargs = {
            'parameters': json_parameters(optional=True),
            'issuer': request.environ.get('issuer'),
            'vo': request.environ.get('vo'),
        }
        try:
            update_rse(rse, **kwargs)
        except (InvalidObject, InputValidationError) as error:
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
        """
        ---
        summary: Get RSE
        description: Get details about a specific RSE.
        tags:
          - Rucio Storage Elements
        parameters:
        - name: rse
          in: path
          description: The name of the Rucio Storage Element name.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  description: The RSE properties.
                  type: object
                  properties:
                    deterministic:
                      description: If the pfn is generated deterministicly.
                      type: boolean
                    volatile:
                      description: RSE cache.
                      type: boolean
                    city:
                      description: The city of the RSE.
                      type: string
                    staging_area:
                      description: Staging area.
                      type: string
                    region_code:
                      description: The region code of the RSE.
                      type: string
                    country_name:
                      description: The country name of the RSE.
                      type: string
                    continent:
                      description: The continent of the RSE.
                      type: string
                    time_zone:
                      description: The time zone of the RSE.
                      type: string
                    ISP:
                      description: The internet service provider of the RSE.
                      type: string
                    rse_type:
                      description: The rse type.
                      type: string
                      enum: ["DISK", "TAPE"]
                    latitute:
                      description: The latitute of the RSE.
                      type: float
                    longitude:
                      description: The longitude of the RSE.
                      type: float
                    ASN:
                      description: The access service network of the RSE.
                      type: string
                    availability:
                      description: The availability of the RSE.
                      type: integer
          401:
            description: Invalid Auth Token
          404:
            description: RSE not found
          406:
            description: Not acceptable
        """
        try:
            rse_prop = get_rse(rse=rse, vo=request.environ.get('vo'))
            return Response(render_json(**rse_prop), content_type="application/json")
        except RSENotFound as error:
            return generate_http_error_flask(404, error)

    def delete(self, rse):
        """
        ---
        summary: Disable RSE
        description: Disable a specific RSE.
        tags:
          - Rucio Storage Elements
        parameters:
        - name: rse
          in: path
          description: The name of the Rucio Storage Element name.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
          401:
            description: Invalid Auth Token
          404:
            description: RSE not found
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
        """
        ---
        summary: Create RSE Attribute
        description: Create a RSE attribute with given RSE name.
        tags:
          - Rucio Storage Elements
        parameters:
        - name: rse
          in: path
          description: The name of the Rucio Storage Element name.
          schema:
            type: string
          style: simple
        - name: key
          in: path
          description: The name of the attribute of the RSE.
          schema:
            type: string
          style: simple
        requestBody:
          content:
            application/json:
              schema:
                type: object
                required:
                - value
                properties:
                  value:
                    description: The value of the RSE attribute.
                    type: string
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          400:
            description: Cannot decode json parameter dictionary
          401:
            description: Invalid Auth Token
          404:
            description: RSE not found
          409:
            description: Attribute already exists
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
        ---
        summary: Get RSE Attributes
        description: Lists all RSE attributes for a RSE.
        tags:
          - Rucio Storage Elements
        parameters:
        - name: rse
          in: path
          description: The name of the Rucio Storage Element name.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  description: The RSE attribute list. Returns a dictionary with the attribute names as keys and the values as values.
                  type: object
                  additionalProperties:
                    type: string
          401:
            description: Invalid Auth Token
          404:
            description: RSE not found
          406:
            description: Not acceptable
        """
        try:
            rse_attr = list_rse_attributes(rse, vo=request.environ.get('vo'))
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except RSENotFound as error:
            return generate_http_error_flask(404, error)

        return jsonify(rse_attr)

    def delete(self, rse, key):
        """
        ---
        summary: Delete RSE Attribute
        description: Delete an RSE attribute for given RSE name.
        tags:
          - Rucio Storage Elements
        parameters:
        - name: rse
          in: path
          description: The name of the Rucio Storage Element name.
          schema:
            type: string
          style: simple
        - name: key
          in: path
          description: The name of the attribute of the RSE.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
          401:
            description: Invalid Auth Token
          404:
            description: RSE or RSE attribute not found
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
        """
        ---
        summary: List RSE Protocols
        description: List all supported protocols of the given RSE.
        tags:
          - Rucio Storage Elements
        parameters:
        - name: rse
          in: path
          description: The name of the Rucio Storage Element name.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  description: Supported RSE Protocols and other information.
                  type: object
                  properties:
                    deterministic:
                      description: If the pfn is generated deterministicly.
                      type: boolean
                    volatile:
                      description: RSE cache.
                      type: boolean
                    staging_area:
                      description: Staging area.
                      type: string
                    rse_type:
                      description: The rse type.
                      type: string
                      enum: ["DISK", "TAPE"]
                    availability_read:
                      description: The read availability of the RSE.
                      type: boolean
                    availability_write:
                      description: The write availability of the RSE.
                      type: boolean
                    availability_delete:
                      description: The delete availability of the RSE.
                      type: boolean
                    credentials:
                      description: The credentials, currently None.
                      type: string
                    domain:
                      description: The domains of the RSE protocols.
                      type: array
                    id:
                      description: The RSE id.
                      type: string
                    lfn2pfn_algorithm:
                      description: The algorithm used to translate the logical file names to the physical ones.
                      type: string
                    qos_class:
                      description: The qos class of the RSE.
                      type: string
                    rse:
                      description: The name of the RSE.
                      type: string
                    sign_url:
                      description: The sign url of the RSE.
                      type: string
                    verify_checksum:
                      description: If the checksum of the files should be verified.
                      type: boolean
                    protocols:
                      description: All supported protocols of the RSE.
                      type: array
                      items:
                        type: object
                        description: A supported RSE protocol.
                        properties:
                          hostname:
                            description: The hostname of the protocol.
                            type: string
                          scheme:
                            description: The scheme of the protocol.
                            type: string
                          port:
                            description: The port of the protocol.
                            type: integer
                          prefix:
                            description: The prefix of the protocol.
                            type: string
                          impl:
                            description: The implementation of the protocol.
                            type: string
                          domains:
                            description: The domains of the protocol.
                            type: object
                            properties:
                              lan:
                                description: The lan domain
                                type: object
                                properties:
                                  read:
                                    description: The read value of the lan protocol.
                                    type: integer
                                  write:
                                    description: The write value of the lan protocol.
                                    type: integer
                                  delete:
                                    description: The delete value of the lan protocol.
                                    type: integer
                              wan:
                                  read:
                                    description: The read value of the wan protocol.
                                    type: integer
                                  write:
                                    description: The read value of the wan protocol.
                                    type: integer
                                  delete:
                                    description: The read value of the wan protocol.
                                    type: integer
                                  third_party_copy_read:
                                    description: The third party copy read value of the wan protocol.
                                    type: integer
                                  third_party_copy_write:
                                    description: The third party copy write value of the wan protocol.
                                    type: integer
                          extended_attributes:
                            description: The extended attributes of the protocol.
                            type: string
          401:
            description: Invalid Auth Token
          404:
            description: RSE not found or RSE Operation, RSE Protocal Doman, RSE Protocol not supported
          406:
            description: Not acceptable
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
        ---
        summary: Translate LFNs to PFNs
        description: Return PFNs for a set of LFNs.  Formatted as a JSON object where the key is a LFN and the value is the corresponding PFN.
        tags:
          - Rucio Storage Elements
        parameters:
        - name: rse
          in: path
          description: The name of the Rucio Storage Element name.
          schema:
            type: string
          style: simple
        - name: schema
          in: path
          description: The protocol identifier.
          schema:
            type: string
          style: simple
          required: False
        - name: lfn
          in: query
          description: The lfns of the request.
          schema:
            type: string
          required: True
        - name: scheme
          in: query
          description: Optional argument to help with the protocol selection (e.g., http / gsiftp / srm)
          schema:
            type: string
        - name: domain
          in: query
          description: Optional argument used to select the protocol for wan or lan use cases.
          schema:
            type: string
        - name: operation
          in: query
          description: Optional query argument to select the protoco for read-vs-writes.
          schema:
            type: string
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  description: The PFNs to the LFNs. Dictionary with lfns as keys and pfns as values.
                  type: object
                  additionalProperties:
                    type:
                      string
          401:
            description: Invalid Auth Token
          404:
            description: RSE not found or RSE Protocol or RSE Protocl Domain not supported
          406:
            description: Not acceptable
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
        ---
        summary: Create RSE Protocol
        description: Create a protocol for a given RSE.
        tags:
          - Rucio Storage Elements
        parameters:
        - name: rse
          in: path
          description: The name of the Rucio Storage Element name.
          schema:
            type: string
          style: simple
        - name: scheme
          in: path
          description: The protocol identifier.
          schema:
            type: string
          style: simple
          required: False
        requestBody:
          content:
            application/json:
              schema:
                type: object
                properties:
                  domains:
                    description: The domains for the protocol.
                    type: array
                  port:
                    description: The port the protocol uses.
                    type: integer
                  hostname:
                    description: The hostname of the protocol.
                    type: string
                  extended_attributes:
                    description: Extended attributes for the protocol.
                    type: string
                  prefix:
                    description: The prefix of the Protocol.
                    type: string
                  impl:
                    description: The impl used by the Protocol.
                    type: string
                  read_lan:
                    description: If the protocol is readable via lan.
                    type: integer
                  write_lan:
                    description: If the protocol is writable via lan.
                    type: integer
                  delete_lan:
                    description: If the protocol is deletable via lan.
                    type: integer
                  read_wan:
                    description: If the protocol is readable via wan.
                    type: integer
                  write_wan:
                    description: If the protocol is writable via wan.
                    type: integer
                  delete_wan:
                    description: If the protocol is deletable via wan.
                    type: integer
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          400:
            description: Cannot decode json parameter dictionary
          401:
            description: Invalid Auth Token
          404:
            description: RSE not found or RSE Protocol Domain not supported
          409:
            description: RSE protocol priority error
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
        """
        ---
        summary: Get Protocols
        description: List all references of the provided RSE for the given protocol.
        tags:
          - Rucio Storage Elements
        parameters:
        - name: rse
          in: path
          description: The name of the Rucio Storage Element name.
          schema:
            type: string
          style: simple
        - name: scheme
          in: path
          description: The protocol identifier.
          schema:
            type: string
          style: simple
          required: False
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  description: A dict with RSE information and supported protocols.
                  type: object
                  properties:
                    deterministic:
                      description: If the pfn is generated deterministicly.
                      type: boolean
                    volatile:
                      description: RSE cache.
                      type: boolean
                    staging_area:
                      description: Staging area.
                      type: string
                    rse_type:
                      description: The rse type.
                      type: string
                      enum: ["DISK", "TAPE"]
                    availability_read:
                      description: The read availability of the RSE.
                      type: boolean
                    availability_write:
                      description: The write availability of the RSE.
                      type: boolean
                    availability_delete:
                      description: The delete availability of the RSE.
                      type: boolean
                    credentials:
                      description: The credentials, currently None.
                      type: string
                    domain:
                      description: The domains of the RSE protocols.
                      type: array
                    id:
                      description: The RSE id.
                      type: string
                    lfn2pfn_algorithm:
                      description: The algorithm used to translate the logical file names to the physical ones.
                      type: string
                    qos_class:
                      description: The qos class of the RSE.
                      type: string
                    rse:
                      description: The name of the RSE.
                      type: string
                    sign_url:
                      description: The sign url of the RSE.
                      type: string
                    verify_checksum:
                      description: If the checksum of the files should be verified.
                      type: boolean
                    protocols:
                      description: All supported protocols of the RSE.
                      type: array
                      items:
                        type: object
                        description: A supported RSE protocol.
                        properties:
                          hostname:
                            description: The hostname of the protocol.
                            type: string
                          scheme:
                            description: The scheme of the protocol.
                            type: string
                          port:
                            description: The port of the protocol.
                            type: integer
                          prefix:
                            description: The prefix of the protocol.
                            type: string
                          impl:
                            description: The implementation of the protocol.
                            type: string
                          domains:
                            description: The domains of the protocol.
                            type: object
                            properties:
                              lan:
                                description: The lan domain
                                type: object
                                properties:
                                  read:
                                    description: The read value of the lan protocol.
                                    type: integer
                                  write:
                                    description: The write value of the lan protocol.
                                    type: integer
                                  delete:
                                    description: The delete value of the lan protocol.
                                    type: integer
                              wan:
                                  read:
                                    description: The read value of the wan protocol.
                                    type: integer
                                  write:
                                    description: The read value of the wan protocol.
                                    type: integer
                                  delete:
                                    description: The read value of the wan protocol.
                                    type: integer
                                  third_party_copy_read:
                                    description: The third party copy read value of the wan protocol.
                                    type: integer
                                  third_party_copy_write:
                                    description: The third party copy write value of the wan protocol.
                                    type: integer
                          extended_attributes:
                            description: The extended attributes of the protocol.
                            type: string
          401:
            description: Invalid Auth Token
          404:
            description: RSE not found or Protocol or Protocol domain not Supported.
          406:
            description: Not acceptable
        """
        try:
            p_list = get_rse_protocols(rse, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except (RSENotFound, RSEProtocolNotSupported, RSEProtocolDomainNotSupported) as error:
            return generate_http_error_flask(404, error)

        return jsonify(p_list)

    def put(self, rse, scheme, hostname=None, port=None):
        """
        ---
        summary: Update Protocol Attributes
        description: Updates attributes of an existing protocol entry. Because protocol identifier, hostname, and port are used as unique identifier they are immutable.
        tags:
          - Rucio Storage Elements
        parameters:
        - name: rse
          in: path
          description: The name of the Rucio Storage Element name.
          schema:
            type: string
          style: simple
        - name: scheme
          in: path
          description: The protocol identifier.
          schema:
            type: string
          style: simple
        - name: hostname
          in: path
          description: The hostname of the protocol.
          schema:
            type: string
          style: simple
          required: False
        - name: port
          in: path
          description: The port of the protocol.
          schema:
            type: integer
          style: simple
          required: False
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  description: A dict with RSE information and supported protocols.
                  type: object
                  properties:
                    deterministic:
                      description: If the pfn is generated deterministicly.
                      type: boolean
                    volatile:
                      description: RSE cache.
                      type: boolean
                    staging_area:
                      description: Staging area.
                      type: string
                    rse_type:
                      description: The rse type.
                      type: string
                      enum: ["DISK", "TAPE"]
                    availability_read:
                      description: The read availability of the RSE.
                      type: boolean
                    availability_write:
                      description: The write availability of the RSE.
                      type: boolean
                    availability_delete:
                      description: The delete availability of the RSE.
                      type: boolean
                    credentials:
                      description: The credentials, currently None.
                      type: string
                    domain:
                      description: The domains of the RSE protocols.
                      type: array
                    id:
                      description: The RSE id.
                      type: string
                    lfn2pfn_algorithm:
                      description: The algorithm used to translate the logical file names to the physical ones.
                      type: string
                    qos_class:
                      description: The qos class of the RSE.
                      type: string
                    rse:
                      description: The name of the RSE.
                      type: string
                    sign_url:
                      description: The sign url of the RSE.
                      type: string
                    verify_checksum:
                      description: If the checksum of the files should be verified.
                      type: boolean
                    protocols:
                      description: All supported protocols of the RSE.
                      type: array
                      items:
                        type: object
                        description: A supported RSE protocol.
                        properties:
                          hostname:
                            description: The hostname of the protocol.
                            type: string
                          scheme:
                            description: The scheme of the protocol.
                            type: string
                          port:
                            description: The port of the protocol.
                            type: integer
                          prefix:
                            description: The prefix of the protocol.
                            type: string
                          impl:
                            description: The implementation of the protocol.
                            type: string
                          domains:
                            description: The domains of the protocol.
                            type: object
                            properties:
                              lan:
                                description: The lan domain
                                type: object
                                properties:
                                  read:
                                    description: The read value of the lan protocol.
                                    type: integer
                                  write:
                                    description: The write value of the lan protocol.
                                    type: integer
                                  delete:
                                    description: The delete value of the lan protocol.
                                    type: integer
                              wan:
                                  read:
                                    description: The read value of the wan protocol.
                                    type: integer
                                  write:
                                    description: The read value of the wan protocol.
                                    type: integer
                                  delete:
                                    description: The read value of the wan protocol.
                                    type: integer
                                  third_party_copy_read:
                                    description: The third party copy read value of the wan protocol.
                                    type: integer
                                  third_party_copy_write:
                                    description: The third party copy write value of the wan protocol.
                                    type: integer
                          extended_attributes:
                            description: The extended attributes of the protocol.
                            type: string
          401:
            description: Invalid Auth Token
          404:
            description: RSE not found or Protocol or Protocol domain not Supported.
          406:
            description: Not acceptable
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
        ---
        summary: Delete Protocol Attributes
        description: Delete all protocol attibutes.
        tags:
          - Rucio Storage Elements
        parameters:
        - name: rse
          in: path
          description: The name of the Rucio Storage Element name.
          schema:
            type: string
          style: simple
        - name: scheme
          in: path
          description: The protocol identifier.
          schema:
            type: string
          style: simple
        - name: hostname
          in: path
          description: The hostname of the protocol.
          schema:
            type: string
          style: simple
          required: False
        - name: port
          in: path
          description: The port of the protocol.
          schema:
            type: integer
          style: simple
          required: False
        responses:
          200:
            description: OK
          401:
            description: Invalid Auth Token
          404:
            description: Rse not found or protocol not supported
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
        ---
        summary: Get Rse Usage Information
        description: Get rse usage information.
        tags:
          - Rucio Storage Elements
        parameters:
        - name: rse
          in: path
          description: The name of the Rucio Storage Element name.
          schema:
            type: string
          style: simple
        - name: per_account
          in: query
          description: Boolean whether the usage should be also calculated per account or not.
          schema:
            type: boolean
        - name: source
          in: query
          description: The information source, e.g., srm.
          schema:
            type: string
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  description: A list with the rse usage.
                  type: array
                  items:
                    type: object
                    properties:
                      rse_id:
                        description: The id of the rse.
                        type: string
                      rse:
                        description: The name of the rse.
                        type: string
                      source:
                        description: The source of the rse.
                        type: string
                      used:
                        description: The number of used bytes.
                        type: integer
                      free:
                        description: The number of free bytes.
                        type: integer
                      total:
                        description: The number of total bytes.
                        type: integer
                      files:
                        description: The number of files.
                        type: integer
                      updated_at:
                        description: The last time it got updated.
                        type: string
          401:
            description: Invalid Auth Token
          404:
            description: Rse not found
          406:
            description: Not acceptable
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
        """
        ---
        summary: Update Rse Usage
        description: Update the RSE Update information.
        tags:
          - Rucio Storage Elements
        parameters:
        - name: rse
          in: path
          description: The name of the Rucio Storage Element name.
          schema:
            type: string
          style: simple
        requestBody:
          content:
            application/json:
              schema:
                type: object
                properties:
                  source:
                    description: The information source, e.g. srm.
                    type: string
                  used:
                    description: The number of used bytes.
                    type: integer
                  free:
                    description: The number of free bytes.
                    type: integer
                  files:
                    description: The number of files.
                    type: integer
        responses:
          200:
            description: OK
          400:
            description: Can not decode json parameter list.
          401:
            description: Invalid Auth Token
          404:
            description: Rse not found
          406:
            description: Not acceptable
        """
        parameters = json_parameters()
        kwargs = {'source': None, 'used': None, 'free': None, 'files': None}
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
        ---
        summary: Get Rse Usage History
        description: Get the rse usage history
        tags:
          - Rucio Storage Elements
        parameters:
        - name: rse
          in: path
          description: The name of the Rucio Storage Element name.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  description: A list with the rse usage history items.
                  type: array
                  items:
                    type: object
                    properties:
                      rse_id:
                        description: The id of the rse.
                        type: string
                      rse:
                        description: The name of the rse.
                        type: string
                      source:
                        description: The source of the rse.
                        type: string
                      used:
                        description: The number of used bytes.
                        type: integer
                      free:
                        description: The number of free bytes.
                        type: integer
                      total:
                        description: The number of total bytes.
                        type: integer
                      updated_at:
                        description: The last time it got updated.
                        type: string
          401:
            description: Invalid Auth Token
          404:
            description: Rse not found
          406:
            description: Not acceptable
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
        ---
        summary: Get Rse Limits
        description: Get the rse limits.
        tags:
          - Rucio Storage Elements
        parameters:
        - name: rse
          in: path
          description: The name of the Rucio Storage Element name.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  description: The limits.
                  type: object
                  additionalProperties:
                    x-additionalPropertiesName: limit name
                    description: An item with the name as key and the value as value.
                    type: integer
          401:
            description: Invalid Auth Token
          404:
            description: Rse not found
          406:
            description: Not acceptable
        """
        try:
            limits = get_rse_limits(rse=rse, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
            return Response(render_json(**limits), content_type="application/json")
        except RSENotFound as error:
            return generate_http_error_flask(404, error)

    def put(self, rse):
        """
        ---
        summary: Update Rse Limit
        description: Update an rse limit.
        tags:
          - Rucio Storage Elements
        parameters:
        - name: rse
          in: path
          description: The name of the Rucio Storage Element name.
          schema:
            type: string
          style: simple
        requestBody:
          content:
            application/json:
              schema:
                type: object
                properties:
                  name:
                    description: The name of the limit.
                    type: string
                  value:
                    description: The value of the limit.
                    type: integer
        responses:
          200:
            description: OK
          401:
            description: Invalid Auth Token
          404:
            description: Rse not found
          406:
            description: Not acceptable
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
        """
        ---
        summary: Delete Rse Limit
        description: Delete an rse limit
        tags:
          - Rucio Storage Elements
        parameters:
        - name: rse
          in: path
          description: The name of the Rucio Storage Element name.
          schema:
            type: string
          style: simple
        requestBody:
          content:
            application/json:
              schema:
                type: object
                required:
                - name
                properties:
                  name:
                    description: The name of the limit.
                    type: string
        responses:
          200:
            description: OK
          401:
            description: Invalid Auth Token
          404:
            description: Rse not found
          406:
            description: Not acceptable
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
        ---
        summary: Get Rse Account Usage and Limit
        description: Returns the usage and limit of an account for a rse.
        tags:
          - Rucio Storage Elements
        parameters:
        - name: rse
          in: path
          description: The name of the Rucio Storage Element name.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  description: A list with the rse account limits and usages.
                  type: array
                  items:
                    type: object
                    properties:
                      rse_id:
                        description: The id of the rse.
                        type: string
                      rse:
                        description: The name of the rse.
                        type: string
                      account:
                        description: The account.
                        type: string
                      used_files:
                        description: The number of used files.
                        type: integer
                      used_bytes:
                        description: The number of used bytes.
                        type: integer
                      quota_bytes:
                        description: The number of quota bytes.
                        type: integer
          401:
            description: Invalid Auth Token
          404:
            description: Rse not found
          406:
            description: Not acceptable
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
        ---
        summary: Get Rse Distances
        description: Returns the distances between a source and destination rse.
        tags:
          - Rucio Storage Elements
        parameters:
        - name: source
          in: path
          description: The name of the source Rucio Storage Element.
          schema:
            type: string
          style: simple
        - name: destination
          in: path
          description: The name of the destination Rucio Storage Element.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  description: The distances between the Rses.
                  type: array
                  items:
                    type: object
                    description: One distance betweeen source and destination.
                    properties:
                      src_rse_id:
                        description: The source rse id.
                        type: string
                      dest_rse_id:
                        description: The destination rse id.
                        type: string
                      ranking:
                        description: The ranking.
                        type: integer
                      agis_distance:
                        description: The agis distance.
                        type: integer
                      geoip_distance:
                        description: The geo ip distance.
                        type: integer
          401:
            description: Invalid Auth Token
          404:
            description: Rse not found
          406:
            description: Not acceptable
        """
        try:
            distance = get_distance(source=source, destination=destination, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
            return Response(dumps(distance, cls=APIEncoder), content_type="application/json")
        except RSENotFound as error:
            return generate_http_error_flask(404, error)

    def post(self, source, destination):
        """
        ---
        summary: Create Rse Distance
        description: Post a rse distance.
        tags:
          - Rucio Storage Elements
        parameters:
        - name: source
          in: path
          description: The name of the source Rucio Storage Element.
          schema:
            type: string
          style: simple
        - name: destination
          in: path
          description: The name of the destination Rucio Storage Element.
          schema:
            type: string
          style: simple
        requestBody:
          content:
            application/json:
              schema:
                type: object
                properties:
                  ranking:
                    description: The ranking of the distance.
                    type: integer
                  distance:
                    description: The distance between the Rses.
                    type: integer
                  geoip_distance:
                    description: The geoip distance between the Rses.
                    type: integer
                  active:
                    description: If the distance is active.
                    type: boolean
                  submitted:
                    description: If the distance is submitted.
                    type: boolean
                  finished:
                    description: If the distance is finished.
                    type: boolean
                  failed:
                    description: If the distance failed.
                    type: boolean
                  transfer_speed:
                    description: The transferspeed between the Rses.
                    type: integer
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          401:
            description: Invalid Auth Token
          404:
            description: Rse not found
          406:
            description: Not acceptable
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
        """
        ---
        summary: Update Rse Distance
        description: Update rse distance information.
        tags:
          - Rucio Storage Elements
        parameters:
        - name: source
          in: path
          description: The name of the source Rucio Storage Element.
          schema:
            type: string
          style: simple
        - name: destination
          in: path
          description: The name of the destination Rucio Storage Element.
          schema:
            type: string
          style: simple
        requestBody:
          content:
            application/json:
              schema:
                type: object
                properties:
                  ranking:
                    description: The ranking of the distance.
                    type: integer
                  agis_distance:
                    description: The distance between the Rses.
                    type: integer
                  geoip_distance:
                    description: The geoip distance between the Rses.
                    type: integer
                  active:
                    description: If the distance is active.
                    type: boolean
                  submitted:
                    description: If the distance is submitted.
                    type: boolean
                  finished:
                    description: If the distance is finished.
                    type: boolean
                  failed:
                    description: If the distance failed.
                    type: boolean
                  transfer_speed:
                    description: The transferspeed between the Rses.
                    type: integer
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          401:
            description: Invalid Auth Token
          404:
            description: Rse not found
          406:
            description: Not acceptable
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

    def delete(self, source, destination):
        """
        ---
        summary: Delete Rse Distance
        description: Delete distance information between source RSE and destination RSE.
        tags:
          - Rucio Storage Elements
        parameters:
        - name: source
          in: path
          description: The name of the source Rucio Storage Element.
          schema:
            type: string
          style: simple
        - name: destination
          in: path
          description: The name of the destination Rucio Storage Element.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Deleted"]
          401:
            description: Invalid Auth Token
          404:
            description: Rse not found
          406:
            description: Not acceptable
        """
        try:
            delete_distance(
                source=source,
                destination=destination,
                issuer=request.environ.get('issuer'),
                vo=request.environ.get('vo')
            )
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except RSENotFound as error:
            return generate_http_error_flask(404, error)

        return 'Deleted', 200


class QoSPolicy(ErrorHandlingMethodView):
    """ Add/Delete/List QoS policies on an RSE. """

    @check_accept_header_wrapper_flask(['application/json'])
    def post(self, rse, policy):
        """
        ---
        summary: Add QoS policy
        description: Add a QoS Policy to a RSE.
        tags:
          - Rucio Storage Elements
        parameters:
        - name: rse
          in: path
          description: The name of the Rucio Storage Element name.
          schema:
            type: string
          style: simple
        - name: policy
          in: path
          description: The QoS policy to add to and rse.
          schema:
            type: string
          style: simple
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          401:
            description: Invalid Auth Token
          404:
            description: Rse not found
          406:
            description: Not acceptable
        """
        try:
            add_qos_policy(rse=rse, qos_policy=policy, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except RSENotFound as error:
            return generate_http_error_flask(404, error)

        return 'Created', 201

    @check_accept_header_wrapper_flask(['application/json'])
    def delete(self, rse, policy):
        """
        ---
        summary: Delete QoS Policy
        description: Delete QoS policy from RSE.
        tags:
          - Rucio Storage Elements
        parameters:
        - name: rse
          in: path
          description: The name of the Rucio Storage Element name.
          schema:
            type: string
          style: simple
        - name: policy
          in: path
          description: The QoS policy to add to and rse.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
          401:
            description: Invalid Auth Token
          404:
            description: Rse not found
          406:
            description: Not acceptable
        """
        try:
            delete_qos_policy(rse=rse, qos_policy=policy, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except RSENotFound as error:
            return generate_http_error_flask(404, error)

        return '', 200

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, rse):
        """
        ---
        summary: Gett QoS Policies
        description: List all QoS policies for an Rse.
        tags:
          - Rucio Storage Elements
        parameters:
        - name: rse
          in: path
          description: The name of the Rucio Storage Element name.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  description: A list with all the QoS policies for an Rse.
                  type: array
                  items:
                    type: object
                    porperties:
                      rse_id:
                        description: The rse id.
                        type: string
                      qos_policy:
                        description: The qos policy.
                        type: string
          401:
            description: Invalid Auth Token
          404:
            description: Rse not found
          406:
            description: Not acceptable
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
    bp.add_url_rule('/<source>/distances/<destination>', view_func=distance_view, methods=['get', 'post', 'put', 'delete'])
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
    bp.add_url_rule('/<rse>/limits', view_func=limits_view, methods=['get', 'put', 'delete'])
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
