# Copyright 2019 CERN for the benefit of the ATLAS collaboration.
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
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020

from json import loads
from traceback import format_exc

from flask import Flask, Blueprint, Response, request
from flask.views import MethodView

from rucio.api.vo import add_vo, list_vos, recover_vo_root_identity, update_vo
from rucio.common.exception import AccessDenied, AccountNotFound, Duplicate, RucioException, VONotFound, UnsupportedOperation
from rucio.common.utils import generate_http_error, render_json
from rucio.web.rest.flaskapi.v1.common import before_request, after_request, check_accept_header_wrapper_flask


class VOs(MethodView):
    """ List all the VOs in the database. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self):
        """ List all VOs.

        .. :quickref: VOs; List all VOs.

        :resheader Content-Type: application/x-json-stream
        :status 200: VOs found.
        :status 401: Invalid Auth Token.
        :status 409: Unsupported operation.
        :status 500: Internal Error.
        :returns: A list containing all VOs.

        """
        try:
            data = ""
            for vo in list_vos(issuer=request.environ.get('issuer'), vo=request.environ.get('vo')):
                data += render_json(**vo) + '\n'
            return Response(data, content_type="application/x-json-stream")
        except AccessDenied as error:
            return generate_http_error(401, 'AccessDenied', error.args[0])
        except UnsupportedOperation as error:
            return generate_http_error(409, 'UnsupportedOperation', error.args[0])
        except RucioException as error:
            return generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(error)
            print(format_exc())
            return error, 500


class VO(MethodView):
    """ Add and update a VO. """

    def post(self, new_vo):
        """ Add a VO with a given name.

        .. :quickref: VO; Add a VOs.

        :param new_vo: VO to be added.
        :<json string description: Desciption of VO.
        :<json string email: Admin email for VO.
        :status 201: VO created successfully.
        :status 401: Invalid Auth Token.
        :status 409: Unsupported operation.
        :status 500: Internal Error.

        """
        json_data = request.data
        kwargs = {'description': None, 'email': None}

        try:
            parameters = json_data and loads(json_data)
            if parameters:
                for param in kwargs:
                    if param in parameters:
                        kwargs[param] = parameters[param]
        except ValueError:
            return generate_http_error(400, 'ValueError', 'Cannot decode json parameter dictionary')
        kwargs['issuer'] = request.environ.get('issuer')
        kwargs['vo'] = request.environ.get('vo')

        try:
            add_vo(new_vo=new_vo, **kwargs)
        except AccessDenied as error:
            return generate_http_error(401, 'AccessDenied', error.args[0])
        except UnsupportedOperation as error:
            return generate_http_error(409, 'UnsupportedOperation', error.args[0])
        except Duplicate as error:
            return generate_http_error(409, 'Duplicate', error.args[0])
        except RucioException as error:
            return generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(error)
            print(format_exc())
            return error, 500

        return "Created", 201

    def put(self, updated_vo):
        """ Update the details for a given VO

        .. :quickref: VO; Update a VOs.

        :param updated_vo: VO to be updated.
        :<json string description: Desciption of VO.
        :<json string email: Admin email for VO.
        :status 200: VO updated successfully.
        :status 401: Invalid Auth Token.
        :status 404: VO not found.
        :status 409: Unsupported operation.
        :status 500: Internal Error.

        """
        json_data = request.data

        try:
            parameters = loads(json_data)
        except ValueError:
            return generate_http_error(400, 'ValueError', 'cannot decode json parameter dictionary')

        try:
            update_vo(updated_vo=updated_vo, parameters=parameters, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except AccessDenied as error:
            return generate_http_error(401, 'AccessDenied', error.args[0])
        except VONotFound as error:
            return generate_http_error(404, 'VONotFound', error.args[0])
        except UnsupportedOperation as error:
            return generate_http_error(409, 'UnsupportedOperation', error.args[0])
        except RucioException as error:
            return generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(error)
            print(format_exc())
            return error, 500

        return "OK", 200


class RecoverVO(MethodView):
    """ Recover root identity for a VO. """

    def post(self, root_vo):
        """ Recover root identity for a given VO

        .. :quickref: RecoverVO; Recover VO root identity.

        :param root_vo: VO to be recovered.
        :<json string identity: Identity key to use.
        :<json string authtype: Type of identity.
        :<json string email: Admin email for VO.
        :<json string email: Password for identity.
        :<json bool default: Whether to use identity as account default.
        :status 201: VO recovered successfully.
        :status 401: Invalid Auth Token.
        :status 404: Account not found.
        :status 409: Unsupported operation.
        :status 500: Internal Error.

        """
        json_data = request.data

        try:
            parameter = loads(json_data)
        except ValueError:
            return generate_http_error(400, 'ValueError', 'cannot decode json parameter dictionary')

        try:
            identity = parameter['identity']
            authtype = parameter['authtype']
            email = parameter['email']
            password = parameter.get('password', None)
            default = parameter.get('default', False)
        except KeyError as error:
            if error.args[0] == 'authtype' or error.args[0] == 'identity' or error.args[0] == 'email':
                return generate_http_error(400, 'KeyError', '%s not defined' % str(error))
        except TypeError:
            return generate_http_error(400, 'TypeError', 'body must be a json dictionary')

        try:
            recover_vo_root_identity(root_vo=root_vo,
                                     identity_key=identity,
                                     id_type=authtype,
                                     email=email,
                                     password=password,
                                     default=default,
                                     issuer=request.environ.get('issuer'),
                                     vo=request.environ.get('vo'))
        except AccessDenied as error:
            return generate_http_error(401, 'AccessDenied', error.args[0])
        except AccountNotFound as error:
            return generate_http_error(404, 'AccountNotFound', error.args[0])
        except Duplicate as error:
            return generate_http_error(409, 'Duplicate', error.args[0])
        except RucioException as error:
            return generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(error)
            print(format_exc())
            return error, 500

        return "Created", 201


"""----------------------
   Web service startup
----------------------"""
bp = Blueprint('vo', __name__)

recover_view = RecoverVO.as_view('recover')
bp.add_url_rule('/<vo>/recover', view_func=recover_view, methods=['post', ])
vo_view = VO.as_view('vo')
bp.add_url_rule('/<vo>', view_func=vo_view, methods=['put', 'post'])
vos_view = VOs.as_view('vos')
bp.add_url_rule('/', view_func=vos_view, methods=['get', ])


application = Flask(__name__)
application.register_blueprint(bp)
application.before_request(before_request)
application.after_request(after_request)


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(bp, url_prefix='/vos')
    return doc_app


if __name__ == "__main__":
    application.run()
