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
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019

from json import dumps, loads
from traceback import format_exc

from web import Created, InternalError, application, ctx, header, loadhook

from rucio.api.vo import add_vo, list_vos
from rucio.common.exception import RucioException
from rucio.common.utils import generate_http_error
from rucio.web.rest.common import (RucioController,
                                   check_accept_header_wrapper, data,
                                   rucio_loadhook)

URLS = ('/', 'VOs',
        '/(.+)', 'VO')


class VOs(RucioController):
    ''' List all the VOs in the database. '''

    @check_accept_header_wrapper(['application/json'])
    def GET(self):
        ''' List all VOs. '''
        header('Content-Type', 'application/json')

        try:
            vos = list_vos(issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(error)
            print(format_exc())
            raise InternalError(error)
        return dumps(vos)


class VO(RucioController):
    ''' Add a VO. '''

    def POST(self, new_vo):
        ''' Add a VO with a given name. '''

        json_data = data()
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
