# -*- coding: utf-8 -*-
# Copyright 2019-2020 CERN
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
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from json import loads
from traceback import format_exc

from web import application, Created, ctx, header, InternalError, loadhook, OK

from rucio.api.vo import add_vo, list_vos, recover_vo_root_identity, update_vo
from rucio.common.exception import AccessDenied, AccountNotFound, Duplicate, RucioException, VONotFound, UnsupportedOperation
from rucio.common.utils import render_json
from rucio.web.rest.common import (RucioController,
                                   check_accept_header_wrapper, data,
                                   rucio_loadhook)
from rucio.web.rest.utils import generate_http_error

URLS = ('/(.+)/recover', 'RecoverVO',
        '/(.+)', 'VO',
        '/', 'VOs')


class VOs(RucioController):
    """ List all the VOs in the database. """

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self):
        """ List all VOs.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            409 Conflict
            500 InternalError

        :returns: A list containing all VOs.
        """
        header('Content-Type', 'application/x-json-stream')

        try:
            for vo in list_vos(issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo')):
                yield render_json(**vo) + '\n'
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except UnsupportedOperation as error:
            raise generate_http_error(409, 'UnsupportedOperation', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(error)
            print(format_exc())
            raise InternalError(error)


class VO(RucioController):
    """ Add and update a VO. """

    def POST(self, new_vo):
        """ Add a VO with a given name.

        HTTP Success:
            201 Created

        HTTP Error:
            401 Unauthorized
            409 Conflict
            500 InternalError

        :param new_vo: VO to be added.
        """
        json_data = data().decode()
        kwargs = {'description': None, 'email': None}

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
            add_vo(new_vo=new_vo, **kwargs)
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except UnsupportedOperation as error:
            raise generate_http_error(409, 'UnsupportedOperation', error.args[0])
        except Duplicate as error:
            raise generate_http_error(409, 'Duplicate', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(error)
            print(format_exc())
            raise InternalError(error)

        raise Created()

    def PUT(self, updated_vo):
        """ Update the details for a given VO

        HTTP Success:
            200 OK

        HTTP Error:
            400 Bad Request
            401 Unauthorized
            404 Not Found
            409 Conflict
            500 InternalError

        :param updated_vo: VO to be updated.
        """
        json_data = data().decode()

        try:
            parameters = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'cannot decode json parameter dictionary')

        try:
            update_vo(updated_vo=updated_vo, parameters=parameters, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except VONotFound as error:
            raise generate_http_error(404, 'VONotFound', error.args[0])
        except UnsupportedOperation as error:
            raise generate_http_error(409, 'UnsupportedOperation', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(error)
            print(format_exc())
            raise InternalError(error)

        raise OK()


class RecoverVO(RucioController):
    """ Recover root identity for a VO. """

    def POST(self, root_vo):
        """ Recover root identity for a given VO

        HTTP Success:
            201 Created

        HTTP Error:
            401 Unauthorized
            404 Not Found
            409 Conflict
            500 InternalError

        :param root_vo: VO to be updated.
        """
        json_data = data().decode()

        try:
            parameter = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'cannot decode json parameter dictionary')

        try:
            identity = parameter['identity']
            authtype = parameter['authtype']
            email = parameter['email']
            password = parameter.get('password', None)
            default = parameter.get('default', False)
        except KeyError as error:
            if error.args[0] == 'authtype' or error.args[0] == 'identity' or error.args[0] == 'email':
                raise generate_http_error(400, 'KeyError', '%s not defined' % str(error))
        except TypeError:
            raise generate_http_error(400, 'TypeError', 'body must be a json dictionary')

        try:
            recover_vo_root_identity(root_vo=root_vo,
                                     identity_key=identity,
                                     id_type=authtype,
                                     email=email,
                                     password=password,
                                     default=default,
                                     issuer=ctx.env.get('issuer'),
                                     vo=ctx.env.get('vo'))
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except AccountNotFound as error:
            raise generate_http_error(404, 'AccountNotFound', error.args[0])
        except Duplicate as error:
            raise generate_http_error(409, 'Duplicate', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(error)
            print(format_exc())
            raise InternalError(error)

        raise Created()


"""----------------------
   Web service startup
----------------------"""

APP = application(URLS, globals())
APP.add_processor(loadhook(rucio_loadhook))
application = APP.wsgifunc()
