#!/usr/bin/env python
# Copyright 2018 CERN for the benefit of the ATLAS collaboration.
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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2012-2013
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2015
# - Cedric Serfon <cedric.serfon@cern.ch>, 2014-2019
# - Martin Barisits <martin.barisits@cern.ch>, 2014-2019
# - Cheng-Hsi Chao <cheng-hsi.chao@cern.ch>, 2014
# - Joaquin Bogado <joaquin.bogado@cern.ch>, 2015
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
#
# PY3K COMPATIBLE

from __future__ import print_function
from datetime import datetime
from json import dumps, loads
from logging import getLogger, StreamHandler, DEBUG
from traceback import format_exc
try:
    from urlparse import parse_qsl
except ImportError:
    from urllib.parse import parse_qsl
from web import application, ctx, data, header, BadRequest, Created, InternalError, OK, loadhook, redirect, seeother

from rucio.api.account import add_account, del_account, get_account_info, list_accounts, list_identities, list_account_attributes, add_account_attribute, del_account_attribute, update_account, get_usage_history
from rucio.api.account_limit import get_local_account_limits, get_local_account_limit, get_local_account_usage, get_global_account_limit, get_global_account_limits, get_global_account_usage
from rucio.api.identity import add_account_identity, del_account_identity
from rucio.api.rule import list_replication_rules
from rucio.api.scope import add_scope, get_scopes
from rucio.common.exception import AccountNotFound, Duplicate, AccessDenied, RucioException, RuleNotFound, RSENotFound, IdentityError, CounterNotFound
from rucio.common.utils import generate_http_error, APIEncoder, render_json
from rucio.web.rest.common import rucio_loadhook, RucioController, check_accept_header_wrapper


LOGGER = getLogger("rucio.account")
SH = StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)

URLS = (
    '/(.+)/attr/', 'Attributes',
    '/(.+)/attr/(.+)', 'Attributes',
    '/(.+)/scopes/', 'Scopes',
    '/(.+)/scopes/(.+)', 'Scopes',
    '/(.+)/identities', 'Identities',
    '/(.+)/limits/local', 'LocalAccountLimits',
    '/(.+)/limits/local/(.+)', 'LocalAccountLimits',
    '/(.+)/limits/global', 'GlobalAccountLimits',
    '/(.+)/limits/global/(.+)', 'GlobalAccountLimits',
    '/(.+)/limits', 'LocalAccountLimits',
    '/(.+)/limits/(.+)', 'LocalAccountLimits',
    '/(.+)/rules', 'Rules',
    '/(.+)/usage/history/(.+)', 'UsageHistory',
    '/(.+)/usage/local', 'LocalUsage',
    '/(.+)/usage/local/(.+)', 'LocalUsage',
    '/(.+)/usage/global', 'GlobalUsage',
    '/(.+)/usage/global/(.+)', 'GlobalUsage',
    '/(.+)/usage/', 'LocalUsage',
    '/(.+)/usage/(.+)', 'LocalUsage',
    '/(.+)', 'AccountParameter',
    '/?$', 'Account',
)


class Attributes(RucioController):

    @check_accept_header_wrapper(['application/json'])
    def GET(self, account):
        """ list all attributes for an account.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found
            406 Not Acceptable
            500 InternalError

        :param Rucio-Account: Account identifier.
        :param Rucio-Auth-Token: as an 32 character hex string.
        :returns: JSON dict containing informations about the requested account.
        """
        header('Content-Type', 'application/json')
        try:
            attribs = list_account_attributes(account, vo=ctx.env.get('vo'))
        except AccountNotFound as error:
            raise generate_http_error(404, 'AccountNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)
        return dumps(attribs)

    def POST(self, account, key):
        """ Add attributes to an account.

        HTTP Success:
            201 Created

        HTTP Error:
            400 Bad Reqeust
            401 Unauthorized
            409 Conflict
            500 Internal Error

        :param account: Account identifier.
        """
        json_data = data().decode()
        try:
            parameter = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'cannot decode json parameter dictionary')

        try:
            key = parameter['key']
            value = parameter['value']
        except KeyError as error:
            if error.args[0] == 'key' or error.args[0] == 'value':
                raise generate_http_error(400, 'KeyError', '%s not defined' % str(error))
        except TypeError:
            raise generate_http_error(400, 'TypeError', 'body must be a json dictionary')

        try:
            add_account_attribute(key=key, value=value, account=account, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except Duplicate as error:
            raise generate_http_error(409, 'Duplicate', error.args[0])
        except AccountNotFound as error:
            raise generate_http_error(404, 'AccountNotFound', error.args[0])
        except Exception as error:
            print(str(format_exc()))
            raise InternalError(error)

        raise Created()

    def DELETE(self, account, key):
        """ disable account with given account name.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found
            500 InternalError

        :param Rucio-Account: Account identifier.
        :param Rucio-Auth-Token: as an 32 character hex string.
        """
        try:
            del_account_attribute(account=account, key=key, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except AccountNotFound as error:
            raise generate_http_error(404, 'AccountNotFound', error.args[0])
        except Exception as error:
            raise InternalError(error)

        raise OK()


class Scopes(RucioController):

    @check_accept_header_wrapper(['application/json'])
    def GET(self, account):
        """ list all scopes for an account.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found
            406 Not Acceptable
            500 InternalError

        :param Rucio-Account: Account identifier.
        :param Rucio-Auth-Token: as an 32 character hex string.
        :returns: A list containing all scope names for an account.
        """
        header('Content-Type', 'application/json')
        try:
            scopes = get_scopes(account, vo=ctx.env.get('vo'))
        except AccountNotFound as error:
            raise generate_http_error(404, 'AccountNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

        if not len(scopes):
            raise generate_http_error(404, 'ScopeNotFound', 'no scopes found for account ID \'%s\'' % account)

        return dumps(scopes)

    def POST(self, account, scope):
        """ create scope with given scope name.

        HTTP Success:
            201 Created

        HTTP Error:
            400 Bad Request
            401 Unauthorized
            404 Not Found
            409 Conflict
            500 Internal Error

        :param Rucio-Auth-Account: Account identifier.
        :param Rucio-Auth-Token: as an 32 character hex string.
        :params Rucio-Account: account belonging to the new scope.
        """
        try:
            add_scope(scope, account, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except Duplicate as error:
            raise generate_http_error(409, 'Duplicate', error.args[0])
        except AccountNotFound as error:
            raise generate_http_error(404, 'AccountNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

        raise Created()


class AccountParameter(RucioController):
    """ create, update, get and disable rucio accounts. """

    @check_accept_header_wrapper(['application/json'])
    def GET(self, account):
        """ get account information for given account name.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found
            406 Not Acceptable
            500 InternalError

        :param Rucio-Account: Account identifier.
        :param Rucio-Auth-Token: as an 32 character hex string.

        :returns: JSON dict containing informations about the requested user.
        """
        header('Content-Type', 'application/json')
        if account == 'whoami':
            # Redirect to the account uri
            frontend = ctx.env.get('HTTP_X_REQUESTED_HOST')
            if frontend:
                raise redirect(frontend + "/accounts/%s" % (ctx.env.get('issuer')))
            raise seeother(ctx.env.get('issuer'))

        acc = None
        try:
            acc = get_account_info(account, vo=ctx.env.get('vo'))
        except AccountNotFound as error:
            raise generate_http_error(404, 'AccountNotFound', error.args[0])
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

        dict = acc.to_dict()

        for key, value in dict.items():
            if isinstance(value, datetime):
                dict[key] = value.strftime('%Y-%m-%dT%H:%M:%S')

        del dict['_sa_instance_state']

        return render_json(**dict)

    def PUT(self, account):
        """ update a parameter for a given account name
        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found
            500 InternalError

        """
        json_data = data().decode()
        try:
            parameter = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'cannot decode json parameter dictionary')
        for key, value in parameter.items():
            try:
                update_account(account, key=key, value=value, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
            except ValueError:
                raise generate_http_error(400, 'ValueError', 'Unknown value %s' % value)
            except AccessDenied as error:
                raise generate_http_error(401, 'AccessDenied', error.args[0])
            except AccountNotFound as error:
                raise generate_http_error(404, 'AccountNotFound', error.args[0])
            except Exception as error:
                raise InternalError(error)

        raise OK()

    def POST(self, account):
        """ create account with given account name.

        HTTP Success:
            201 Created

        HTTP Error:
            400 Bad Reqeust
            401 Unauthorized
            409 Conflict
            500 Internal Error

        :param Rucio-Account: Account identifier.
        :param Rucio-Auth-Token: as an 32 character hex string.
        :params Rucio-Type: the type of the new account.
        """
        json_data = data().decode()
        try:
            parameter = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'cannot decode json parameter dictionary')

        type, email = None, None
        try:
            type = parameter['type']
        except KeyError as error:
            if error.args[0] == 'type':
                raise generate_http_error(400, 'KeyError', '%s not defined' % str(error))
        except TypeError:
            raise generate_http_error(400, 'TypeError', 'body must be a json dictionary')
        try:
            email = parameter['email']
        except KeyError as error:
            if error.args[0] == 'email':
                raise generate_http_error(400, 'KeyError', '%s not defined' % str(error))
        except TypeError:
            raise generate_http_error(400, 'TypeError', 'body must be a json dictionary')

        try:
            add_account(account, type, email, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
        except Duplicate as error:
            raise generate_http_error(409, 'Duplicate', error.args[0])
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

        raise Created()

    def DELETE(self, account):
        """ disable account with given account name.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found
            500 InternalError

        :param Rucio-Account: Account identifier.
        :param Rucio-Auth-Token: as an 32 character hex string.
        """

        try:
            del_account(account, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except AccountNotFound as error:
            raise generate_http_error(404, 'AccountNotFound', error.args[0])
        except Exception as error:
            raise InternalError(error)

        raise OK()


class Account(RucioController):

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self):
        """ list all rucio accounts.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            406 Not Acceptable
            500 InternalError

        :param Rucio-Account: Account identifier.
        :param Rucio-Auth-Token: as an 32 character hex string.
        :returns: A list containing all account names as dict.
        """
        header('Content-Type', 'application/x-json-stream')
        filter = {}
        if ctx.query:
            filter = dict(parse_qsl(ctx.query[1:]))

        for account in list_accounts(filter=filter, vo=ctx.env.get('vo')):
            yield render_json(**account) + "\n"


class LocalAccountLimits(RucioController):

    @check_accept_header_wrapper(['application/json'])
    def GET(self, account, rse=None):
        """ get the current limits for an account on a specific RSE

        HTTP Success:
            200 OK

        HTTP Error:
            404 Not Found
            406 Not Acceptable
            500 InternalError

        :param X-Rucio-Account: Account identifier.
        :param X-Rucio-Auth-Token: as an 32 character hex string.

        :param account:   The account name.
        :param rse:       The rse name.

        :returns: JSON dict containing informations about the requested user.
        """
        header('Content-Type', 'application/json')
        try:
            if rse:
                limits = get_local_account_limit(account=account, rse=rse, vo=ctx.env.get('vo'))
            else:
                limits = get_local_account_limits(account=account, vo=ctx.env.get('vo'))
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])

        return render_json(**limits)

    def PUT(self):
        """ update the limits for an account """
        raise BadRequest()

    def POST(self):
        """ set the limits for an account """
        raise BadRequest()

    def DELETE(self):
        raise BadRequest()


class GlobalAccountLimits(RucioController):

    @check_accept_header_wrapper(['application/json'])
    def GET(self, account, rse_expression=None):
        """ get the current limits for an account on a specific RSE

        HTTP Success:
            200 OK

        HTTP Error:
            404 Not Found
            406 Not Acceptable
            500 InternalError

        :param X-Rucio-Account: Account identifier.
        :param X-Rucio-Auth-Token: as an 32 character hex string.

        :param account:        The account name.
        :param rse_expression: The rse expression.

        :returns: JSON dict containing informations about the requested user.
        """
        header('Content-Type', 'application/json')
        try:
            if rse_expression:
                limits = get_global_account_limit(account=account, rse_expression=rse_expression, vo=ctx.env.get('vo'))
            else:
                limits = get_global_account_limits(account=account, vo=ctx.env.get('vo'))
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])

        return render_json(**limits)

    def PUT(self):
        """ update the limits for an account """
        raise BadRequest()

    def POST(self):
        """ set the limits for an account """
        raise BadRequest()

    def DELETE(self):
        raise BadRequest()


class Identities(RucioController):
    def POST(self, account):
        """ Grant an identity access to an account.

        HTTP Success:
            201 Created

        HTTP Error:
            400 Bad Reqeust
            401 Unauthorized
            409 Conflict
            500 Internal Error

        :param account: Account identifier.
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
            add_account_identity(identity_key=identity, id_type=authtype, account=account, email=email,
                                 password=password, issuer=ctx.env.get('issuer'), default=default, vo=ctx.env.get('vo'))
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except Duplicate as error:
            raise generate_http_error(409, 'Duplicate', error.args[0])
        except AccountNotFound as error:
            raise generate_http_error(404, 'AccountNotFound', error.args[0])
        except IdentityError as error:
            raise generate_http_error(400, 'IdentityError', error.args[0])
        except Exception as error:
            print(str(format_exc()))
            raise InternalError(error)

        raise Created()

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self, account):
        header('Content-Type', 'application/x-json-stream')
        try:
            for identity in list_identities(account, vo=ctx.env.get('vo')):
                yield render_json(**identity) + "\n"
        except AccountNotFound as error:
            raise generate_http_error(404, 'AccountNotFound', error.args[0])
        except Exception as error:
            print(str(format_exc()))
            raise InternalError(error)

    def PUT(self):
        """ update the limits for an account """
        raise BadRequest()

    def DELETE(self, account):

        """ Delete an account's identity mapping.

        HTTP Success:
            200 Created

        HTTP Error:
            400 Bad Reqeust
            401 Unauthorized
            404 Not Found
            500 Internal Error
        :param account: Account identifier.
        """
        json_data = data().decode()
        try:
            parameter = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'cannot decode json parameter dictionary')
        try:
            identity = parameter['identity']
            authtype = parameter['authtype']
        except KeyError as error:
            if error.args[0] == 'authtype' or error.args[0] == 'identity':
                raise generate_http_error(400, 'KeyError', '%s not defined' % str(error))
        except TypeError:
            raise generate_http_error(400, 'TypeError', 'body must be a json dictionary')
        try:
            del_account_identity(identity, authtype, account, ctx.env.get('issuer'), vo=ctx.env.get('vo'))
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except AccountNotFound as error:
            raise generate_http_error(404, 'AccountNotFound', error.args[0])
        except IdentityError as error:
            raise generate_http_error(404, 'IdentityError', error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

        raise OK()


class Rules(RucioController):

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self, account):
        """
        Return all rules of a given account.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            406 Not Acceptable
            404 Not Found

        :param scope: The scope name.
        """
        header('Content-Type', 'application/x-json-stream')
        filters = {'account': account}
        if ctx.query:
            params = dict(parse_qsl(ctx.query[1:]))
            filters.update(params)

        try:
            for rule in list_replication_rules(filters=filters, vo=ctx.env.get('vo')):
                yield dumps(rule, cls=APIEncoder) + '\n'
        except RuleNotFound as error:
            raise generate_http_error(404, 'RuleNotFound', error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

    def PUT(self):
        raise BadRequest()

    def POST(self):
        raise BadRequest()

    def DELETE(self):
        raise BadRequest()


class UsageHistory(RucioController):

    @check_accept_header_wrapper(['application/json'])
    def GET(self, account, rse):
        """
        Return the account usage of the account.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found
            406 Not Acceptable
            500 Internal Error

        :param account: The account name.
        :param rse:     The rse.
        """
        header('Content-Type', 'application/json')
        try:
            usage = get_usage_history(account=account, rse=rse, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
        except AccountNotFound as error:
            raise generate_http_error(404, 'AccountNotFound', error.args[0])
        except CounterNotFound as error:
            raise generate_http_error(404, 'CounterNotFound', error.args[0])
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

        for entry in usage:
            for key, value in entry.items():
                if isinstance(value, datetime):
                    entry[key] = value.strftime('%Y-%m-%dT%H:%M:%S')

        return dumps(usage)


class LocalUsage(RucioController):

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self, account, rse=None):
        """
        Return the account usage of the account.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            406 Not Acceptable
            404 Not Found

        :param account: The account name.
        """
        header('Content-Type', 'application/x-json-stream')
        try:
            for usage in get_local_account_usage(account=account, rse=rse, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo')):
                yield dumps(usage, cls=APIEncoder) + '\n'
        except AccountNotFound as error:
            raise generate_http_error(404, 'AccountNotFound', error.args[0])
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

    def PUT(self):
        raise BadRequest()

    def POST(self):
        raise BadRequest()

    def DELETE(self):
        raise BadRequest()


class GlobalUsage(RucioController):

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self, account, rse_expression=None):
        """
        Return the account usage of the account.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            406 Not Acceptable
            404 Not Found

        :param account:        The account name.
        :param rse_expression: The RSE expression.
        """
        header('Content-Type', 'application/x-json-stream')
        try:
            for usage in get_global_account_usage(account=account, rse_expression=rse_expression, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo')):
                yield dumps(usage, cls=APIEncoder) + '\n'
        except AccountNotFound as error:
            raise generate_http_error(404, 'AccountNotFound', error.args[0])
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

    def PUT(self):
        raise BadRequest()

    def POST(self):
        raise BadRequest()

    def DELETE(self):
        raise BadRequest()


"""----------------------
   Web service startup
----------------------"""

APP = application(URLS, globals())
APP.add_processor(loadhook(rucio_loadhook))
application = APP.wsgifunc()
