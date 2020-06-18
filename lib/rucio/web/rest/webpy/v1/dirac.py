#!/usr/bin/env python
# Copyright 2020 CERN
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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2020
#
# PY3K COMPATIBLE

from __future__ import print_function
from traceback import format_exc
from web import application, ctx, Created, data, InternalError, loadhook, unloadhook

from rucio.api.dirac import add_files
from rucio.common.exception import (AccessDenied, DataIdentifierAlreadyExists, InvalidType,
                                    DatabaseException, Duplicate, InvalidPath,
                                    ResourceTemporaryUnavailable, RucioException,
                                    RSENotFound)
from rucio.common.utils import generate_http_error, parse_response
from rucio.web.rest.common import rucio_loadhook, rucio_unloadhook, RucioController

URLS = ('/addfiles/?$', 'AddFiles')


class AddFiles(RucioController):

    def POST(self):
        """
        Create file replicas at a given RSE.

        HTTP Success:
            201 Created

        HTTP Error:
            401 Unauthorized
            409 Conflict
            500 Internal Error
        """
        json_data = data()
        try:
            parameters = parse_response(json_data)
        except (ValueError, InvalidType):
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            add_files(lfns=parameters['lfns'], issuer=ctx.env.get('issuer'), ignore_availability=parameters.get('ignore_availability', False))
        except InvalidPath as error:
            raise generate_http_error(400, 'InvalidPath', error.args[0])
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except Duplicate as error:
            raise generate_http_error(409, 'Duplicate', error.args[0])
        except DataIdentifierAlreadyExists as error:
            raise generate_http_error(409, 'DataIdentifierAlreadyExists', error.args[0])
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except DatabaseException as error:
            raise generate_http_error(503, 'DatabaseException', error.args[0])
        except ResourceTemporaryUnavailable as error:
            raise generate_http_error(503, 'ResourceTemporaryUnavailable', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)
        raise Created()


"""----------------------
   Web service startup
----------------------"""

APP = application(URLS, globals())
APP.add_processor(loadhook(rucio_loadhook))
APP.add_processor(unloadhook(rucio_unloadhook))
application = APP.wsgifunc()
