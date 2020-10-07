# -*- coding: utf-8 -*-
# Copyright 2014-2020 CERN
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
# - Martin Barisits <martin.barisits@cern.ch>, 2014
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017
# - Thomas Beermann <thomas.beermann@cern.ch>, 2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Muhammad Aditya Hilmy <didithilmy@gmail.com>, 2020
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from __future__ import print_function

from json import loads
from traceback import format_exc

from flask import Flask, Blueprint, request
from flask.views import MethodView

from rucio.api.account_limit import set_local_account_limit, delete_local_account_limit, set_global_account_limit, delete_global_account_limit
from rucio.common.exception import RSENotFound, AccessDenied, AccountNotFound
from rucio.web.rest.flaskapi.v1.common import request_auth_env, response_headers
from rucio.web.rest.utils import generate_http_error_flask


class LocalAccountLimit(MethodView):
    def post(self, account, rse):
        """ Create or update an account limit.

        .. :quickref: LocalAccountLimit; Create/update local account limits.

        :param account: Account name.
        :param rse: RSE name.
        :status 201: Successfully created or updated.
        :status 401: Invalid auth token.
        :status 404: RSE not found.
        :status 404: Account not found
        """
        json_data = request.data
        try:
            parameter = loads(json_data)
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'cannot decode json parameter dictionary')
        try:
            bytes = parameter['bytes']
        except KeyError as error:
            if error.args[0] == 'type':
                return generate_http_error_flask(400, 'KeyError', '%s not defined' % str(error))
            raise
        except TypeError:
            return generate_http_error_flask(400, 'TypeError', 'body must be a json dictionary')

        try:
            set_local_account_limit(account=account, rse=rse, bytes=bytes, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except AccessDenied as error:
            return generate_http_error_flask(401, 'AccessDenied', error.args[0])
        except RSENotFound as error:
            return generate_http_error_flask(404, 'RSENotFound', error.args[0])
        except AccountNotFound as error:
            return generate_http_error_flask(404, 'AccountNotFound', error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500

        return 'Created', 201

    def delete(self, account, rse):
        """ Delete an account limit.

        .. :quickref: LocalAccountLimit; Delete local account limits.

        :param account: Account name.
        :param rse: RSE name.
        :status 200: Successfully deleted.
        :status 401: Invalid auth token.
        :status 404: RSE not found.
        :status 404: Account not found
        """
        try:
            delete_local_account_limit(account=account, rse=rse, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except AccessDenied as error:
            return generate_http_error_flask(401, 'AccessDenied', error.args[0])
        except AccountNotFound as error:
            return generate_http_error_flask(404, 'AccountNotFound', error.args[0])
        except RSENotFound as error:
            return generate_http_error_flask(404, 'RSENotFound', error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500
        return '', 200


class GlobalAccountLimit(MethodView):
    def post(self, account, rse_expression):
        """ Create or update an account limit.

        .. :quickref: GlobalAccountLimit; Create/update global account limits.

        :param account: Account name.
        :param rse_expression: RSE name.
        :status 201: Successfully created or updated.
        :status 401: Invalid auth token.
        :status 404: RSE not found.
        :status 404: Account not found
        """
        json_data = request.data
        try:
            parameter = loads(json_data)
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'cannot decode json parameter dictionary')
        try:
            bytes = parameter['bytes']
        except KeyError as error:
            if error.args[0] == 'type':
                return generate_http_error_flask(400, 'KeyError', '%s not defined' % str(error))
            raise
        except TypeError:
            return generate_http_error_flask(400, 'TypeError', 'body must be a json dictionary')

        try:
            set_global_account_limit(account=account, rse_expression=rse_expression, bytes=bytes, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except AccessDenied as error:
            return generate_http_error_flask(401, 'AccessDenied', error.args[0])
        except RSENotFound as error:
            return generate_http_error_flask(404, 'RSENotFound', error.args[0])
        except AccountNotFound as error:
            return generate_http_error_flask(404, 'AccountNotFound', error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500

        return 'Created', 201

    def delete(self, account, rse_expression):
        """ Delete an account limit.

        .. :quickref: GlobalAccountLimit; Delete global account limits.

        :param account: Account name.
        :param rse_expression: RSE name.
        :status 200: Successfully deleted.
        :status 401: Invalid auth token.
        :status 404: RSE not found.
        :status 404: Account not found
        """
        try:
            delete_global_account_limit(account=account, rse_expression=rse_expression, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except AccessDenied as error:
            return generate_http_error_flask(401, 'AccessDenied', error.args[0])
        except AccountNotFound as error:
            return generate_http_error_flask(404, 'AccountNotFound', error.args[0])
        except RSENotFound as error:
            return generate_http_error_flask(404, 'RSENotFound', error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500
        return '', 200


def blueprint(no_doc=True):
    bp = Blueprint('account_limit', __name__, url_prefix='/accountlimits')

    local_account_limit_view = LocalAccountLimit.as_view('local_account_limit')
    bp.add_url_rule('/local/<account>/<rse>', view_func=local_account_limit_view, methods=['post', 'delete'])
    if no_doc:
        bp.add_url_rule('/<account>/<rse>', view_func=local_account_limit_view, methods=['post', 'delete'])
    global_account_limit_view = GlobalAccountLimit.as_view('global_account_limit')
    bp.add_url_rule('/global/<account>/<rse_expression>', view_func=global_account_limit_view, methods=['post', 'delete'])

    bp.before_request(request_auth_env)
    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint(no_doc=False))
    return doc_app
