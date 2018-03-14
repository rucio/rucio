#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012-2013, 2018
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2015
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2014-2015
# - Martin Barisits, <martin.barisits@cern.ch>, 2014
# - Cheng-Hsi Chao, <cheng-hsi.chao@cern.ch>, 2014
# - Joaquin Bogado, <joaquin.bogado@cern.ch>, 2015

from datetime import datetime
from json import dumps, loads
from logging import getLogger, StreamHandler, DEBUG
from traceback import format_exc
from flask import Flask, Blueprint, Response, request, redirect
from flask.views import MethodView

from rucio.api.account import add_account, del_account, get_account_info, list_accounts, list_identities, list_account_attributes, add_account_attribute, del_account_attribute, set_account_status
from rucio.api.identity import add_account_identity, del_account_identity
from rucio.api.account_limit import get_account_limits, get_account_limit, get_account_usage
from rucio.api.rule import list_replication_rules
from rucio.api.scope import add_scope, get_scopes
from rucio.common.exception import AccountNotFound, Duplicate, AccessDenied, RucioException, RuleNotFound, RSENotFound, IdentityError
from rucio.common.utils import generate_http_error_flask, APIEncoder, render_json
from rucio.web.rest.flaskapi.v1.common import before_request, after_request


LOGGER = getLogger("rucio.account")
SH = StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)


class Attributes(MethodView):

    def get(self, account):
        """ list all attributes for an account.

        .. :quickref: Attributes; list account attributes.

        :param account: The account identifier.
        :resheader Content-Type: application/json
        :status 200: OK
        :status 401: Invalid auth token.
        :status 404: Account not found.
        :status 500: Database Exception.
        :returns: JSON dict containing informations about the requested account.
        """
        try:
            attribs = list_account_attributes(account)
        except AccountNotFound, e:
            return generate_http_error_flask(404, 'AccountNotFound', e.args[0][0])
        except RucioException, e:
            return generate_http_error_flask(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            return e, 500
        return Response(dumps(attribs), content_type="application/json")

    def post(self, account, key):
        """ Add attributes to an account.

        .. :quickref: Attributes; Add account attribute

        :param account: Account identifier.
        :param key: The attribute key.
        :<json string key: The attribute key.
        :<json string value: The attribute value.
        :status 201: Successfully created.
        :status 401: Invalid auth token.
        :status 409: Attribute already exists.
        :status 404: Account not found.
        :status 500: Database Exception.
        """
        json_data = request.data
        try:
            parameter = loads(json_data)
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'cannot decode json parameter dictionary')

        try:
            key = parameter['key']
            value = parameter['value']
        except KeyError, e:
            if e.args[0] == 'key' or e.args[0] == 'value':
                return generate_http_error_flask(400, 'KeyError', '%s not defined' % str(e))
        except TypeError:
            return generate_http_error_flask(400, 'TypeError', 'body must be a json dictionary')

        try:
            add_account_attribute(key=key, value=value, account=account, issuer=request.environ.get('issuer'))
        except AccessDenied, e:
            return generate_http_error_flask(401, 'AccessDenied', e.args[0][0])
        except Duplicate as e:
            return generate_http_error_flask(409, 'Duplicate', e.args[0][0])
        except AccountNotFound, e:
            return generate_http_error_flask(404, 'AccountNotFound', e.args[0][0])
        except Exception, e:
            print str(format_exc())
            return e, 500

        return "Created", 201

    def delete(self, account, key):
        """ Remove attribute from account.

        .. :quickref: Attributes; Delete account attribute

        :param account: Account identifier.
        :param key: The attribute key.
        :status 200: Successfully deleted.
        :status 401: Invalid auth token.
        :status 404: Account not found.
        :status 500: Database Exception.
        """
        try:
            del_account_attribute(account=account, key=key, issuer=request.environ.get('issuer'))
        except AccessDenied, e:
            return generate_http_error_flask(401, 'AccessDenied', e.args[0][0])
        except AccountNotFound, e:
            return generate_http_error_flask(404, 'AccountNotFound', e.args[0][0])
        except Exception, e:
            return e, 500

        return "OK", 200


class Scopes(MethodView):
    def get(self, account):
        """ list all scopes for an account.

        .. :quickref: Scopes; List scope for account.

        :param account: The account identifier.
        :resheader Content-Type: application/x-json-stream
        :status 200: OK.
        :status 401: Invalid auth token.
        :status 404: Account not found.
        :status 404: Scope not found.
        :status 500: Database exception.
        :returns: A list containing all scope names for an account.
        """
        try:
            scopes = get_scopes(account)
        except AccountNotFound, e:
            return generate_http_error_flask(404, 'AccountNotFound', e.args[0][0])
        except RucioException, e:
            return generate_http_error_flask(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            return e, 500

        if not len(scopes):
            return generate_http_error_flask(404, 'ScopeNotFound', 'no scopes found for account ID \'%s\'' % account)

        return Response(dumps(scopes), content_type="application/json")

    def post(self, account, scope):
        """ create scope with given scope name.

        .. :quickref: Scope; Add to account.

        :param account: The account identifier.
        :param scope: The scope to be added.
        :status 201: Successfully added.
        :status 401: Invalid auth token.
        :status 404: Account not found.
        :status 409: Scope already exists.
        :status 500: Database exception.
        """
        try:
            add_scope(scope, account, issuer=request.environ.get('issuer'))
        except AccessDenied, e:
            return generate_http_error_flask(401, 'AccessDenied', e.args[0][0])
        except Duplicate, e:
            return generate_http_error_flask(409, 'Duplicate', e.args[0][0])
        except AccountNotFound, e:
            return generate_http_error_flask(404, 'AccountNotFound', e.args[0][0])
        except RucioException, e:
            return generate_http_error_flask(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            return e, 500

        return "Created", 201


class AccountParameter(MethodView):
    """ create, update, get and disable rucio accounts. """

    def get(self, account):
        """ get account parameters for given account name.

        .. :quickref: AccountParameter; Get account parameters.

        :param account: The account identifier.
        :status 200: OK.
        :status 401: Invalid auth token.
        :status 404: Account not found.
        :status 500: Database exception.
        :returns: JSON dict containing informations about the requested user.
        """
        if account == 'whoami':
            # Redirect to the account uri
            frontend = request.environ.get('HTTP_X_REQUESTED_HOST')
            if frontend:
                return redirect(frontend + "/accounts/%s" % (request.environ.get('issuer')), code=302)
            return redirect(request.environ.get('issuer'), code=303)

        acc = None
        try:
            acc = get_account_info(account)
        except AccountNotFound, e:
            return generate_http_error_flask(404, 'AccountNotFound', e.args[0][0])
        except AccessDenied, e:
            return generate_http_error_flask(401, 'AccessDenied', e.args[0][0])
        except RucioException, e:
            return generate_http_error_flask(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            return e, 500

        dict = acc.to_dict()

        for key, value in dict.items():
            if isinstance(value, datetime):
                dict[key] = value.strftime('%Y-%m-%dT%H:%M:%S')

        del dict['_sa_instance_state']

        return Response(render_json(**dict), content_type="application/json")

    def put(self, account):
        """ update the status for a given account name

        .. :quickref: AccountParameter; Update account information.

        :param account: The account identifier.
        :status 200: OK.
        :status 400: Unknown status.
        :status 401: Invalid auth token.
        :status 404: Account not found.
        :status 500: Database exception.
        """
        json_data = request.data
        try:
            parameter = loads(json_data)
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'cannot decode json parameter dictionary')
        status = parameter.get('status', 'ACTIVE')
        try:
            set_account_status(account, status=status, issuer=request.environ.get('issuer'))
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Unknown status %s' % status)
        except AccessDenied, e:
            return generate_http_error_flask(401, 'AccessDenied', e.args[0][0])
        except AccountNotFound, e:
            return generate_http_error_flask(404, 'AccountNotFound', e.args[0][0])
        except Exception, e:
            return e, 500

        return "OK", 200

    def post(self, account):
        """ create account with given account name.

        .. :quickref: AccountParameter; Add account.

        :param account: The account identifier.
        :<json string type: The account type.
        :<json string email: The account email.
        :status 201: Successfully created.
        :status 401: Invalid auth token.
        :status 409: Account already exists.
        :status 500: Database exception.
        """
        json_data = request.data
        try:
            parameter = loads(json_data)
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'cannot decode json parameter dictionary')

        type, email = None, None
        try:
            type = parameter['type']
        except KeyError, e:
            if e.args[0] == 'type':
                return generate_http_error_flask(400, 'KeyError', '%s not defined' % str(e))
        except TypeError:
            return generate_http_error_flask(400, 'TypeError', 'body must be a json dictionary')
        try:
            email = parameter['email']
        except KeyError, e:
            if e.args[0] == 'email':
                return generate_http_error_flask(400, 'KeyError', '%s not defined' % str(e))
        except TypeError:
            return generate_http_error_flask(400, 'TypeError', 'body must be a json dictionary')

        try:
            add_account(account, type, email, issuer=request.environ.get('issuer'))
        except Duplicate as e:
            return generate_http_error_flask(409, 'Duplicate', e.args[0][0])
        except AccessDenied, e:
            return generate_http_error_flask(401, 'AccessDenied', e.args[0][0])
        except RucioException, e:
            return generate_http_error_flask(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            return e, 500

        return "Created", 201

    def delete(self, account):
        """ disable account with given account name.

        .. :quickref: AccountParameter; Delete account information.

        :param account: The account identifier.
        :status 200: OK.
        :status 401: Invalid auth token.
        :status 404: Account not found.
        :status 500: Database exception.
        """
        try:
            del_account(account, issuer=request.environ.get('issuer'))
        except AccessDenied, e:
            return generate_http_error_flask(401, 'AccessDenied', e.args[0][0])
        except AccountNotFound, e:
            return generate_http_error_flask(404, 'AccountNotFound', e.args[0][0])
        except Exception, e:
            return e, 500

        return "OK", 200


class Account(MethodView):
    def get(self):
        """ list all rucio accounts.

        .. :quickref: Account; List all accounts.

        :resheader Content-Type: application/x-json-stream
        :status 200: OK.
        :status 401: Invalid auth token.
        :status 500: Database exception
        :returns: A list containing all account names as dict.
        """

        filter = {}
        for k, v in request.args.items():
            filter[k] = v

        data = ""
        for account in list_accounts(filter=filter):
            data += render_json(**account) + "\n"

        return Response(data, content_type="application/x-json-stream")


class AccountLimits(MethodView):
    def get(self, account, rse=None):
        """ get the current limits for an account on a specific RSE

        .. :quickref: AccountLimits; Get account limits.

        :param account: The account name.
        :param rse: The rse name.
        :resheader Content-Type: application/json
        :status 200: OK.
        :status 401: Invalid auth token.
        :status 404: RSE not found.
        :status 500: Database exception
        :returns: JSON dict containing informations about the requested user.
        """

        try:
            if rse:
                limits = get_account_limit(account=account, rse=rse)
            else:
                limits = get_account_limits(account=account)
        except RSENotFound, e:
            return generate_http_error_flask(404, 'RSENotFound', e.args[0][0])

        return Response(render_json(**limits), content_type="application/json")


class Identities(MethodView):
    def post(self, account):
        """ Grant an identity access to an account.

        .. :quickref: Identities; Add identity to account.

        :param account: Account identifier.
        :<json string identity: The identity name.
        :<json string authtype: The auth type of the identity.
        :<json string email: The email address.
        :status 201: Successfully added.
        :status 400: Parameter missing.
        :status 401: Invalid auth token.
        :status 409: Already exists.
        :status 404: Account not found.
        :status 500: Database exception.
        """
        json_data = request.data
        try:
            parameter = loads(json_data)
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'cannot decode json parameter dictionary')

        try:
            identity = parameter['identity']
            authtype = parameter['authtype']
            email = parameter['email']
        except KeyError, e:
            if e.args[0] == 'authtype' or e.args[0] == 'identity' or e.args[0] == 'email':
                return generate_http_error_flask(400, 'KeyError', '%s not defined' % str(e))
        except TypeError:
                return generate_http_error_flask(400, 'TypeError', 'body must be a json dictionary')

        try:
            add_account_identity(identity_key=identity, id_type=authtype, account=account, email=email, issuer=request.environ.get('issuer'))
        except AccessDenied, e:
            return generate_http_error_flask(401, 'AccessDenied', e.args[0][0])
        except Duplicate as e:
            return generate_http_error_flask(409, 'Duplicate', e.args[0][0])
        except AccountNotFound, e:
            return generate_http_error_flask(404, 'AccountNotFound', e.args[0][0])
        except Exception, e:
            print str(format_exc())
            return e, 500

        return "Created", 201

    def get(self, account):
        """
        Get all identities mapped to an account.

        .. :quickref: Identities; Get account idenitity mapping.

        :resheader Content-Type: application/x-json-stream
        :param account: The account identifier.
        :status 200: OK.
        :status 401: Invalid auth token.
        :status 404: Account not found.
        :status 500: Database exception
        :returns: Line separated dicts of identities.
        """

        try:
            data = ""
            for identity in list_identities(account):
                data += render_json(**identity) + "\n"
            return Response(data, content_type="application/x-json-stream")
        except AccountNotFound, e:
            return generate_http_error_flask(404, 'AccountNotFound', e.args[0][0])
        except Exception, e:
            print e
            print str(format_exc())
            return e, 500

    def delete(self, account):

        """ Delete an account's identity mapping.

        .. :quickref: Identities; Remove identity from account.

        :param account: Account identifier.
        :<json string identity: The identity name.
        :<json string authtype: The authentication type.
        :status 200: Successfully deleted.
        :status 401: Invalid auth token.
        :status 404: Account not found.
        :status 404: Identity not found.
        :status 500: Database exception.
        """
        json_data = request.data
        try:
            parameter = loads(json_data)
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'cannot decode json parameter dictionary')
        try:
            identity = parameter['identity']
            authtype = parameter['authtype']
        except KeyError, e:
            if e.args[0] == 'authtype' or e.args[0] == 'identity':
                return generate_http_error_flask(400, 'KeyError', '%s not defined' % str(e))
        except TypeError:
            return generate_http_error_flask(400, 'TypeError', 'body must be a json dictionary')
        try:
            del_account_identity(identity, authtype, account)
        except AccessDenied, e:
            return generate_http_error_flask(401, 'AccessDenied', e.args[0][0])
        except AccountNotFound, e:
            return generate_http_error_flask(404, 'AccountNotFound', e.args[0][0])
        except IdentityError, e:
            return generate_http_error_flask(404, 'IdentityError', e.args[0][0])
        except Exception, e:
            print format_exc()
            return e, 500

        return "OK", 200


class Rules(MethodView):

    def get(self, account):
        """
        Return all rules of a given account.

        .. :quickref: Rules; Get rules for account.

        :param scope: The scope name.
        :resheader Content-Type: application/x-json-stream
        :status 200: OK.
        :status 401: Invalid auth token.
        :status 404: Rule not found.
        :status 500: Database exception.
        :returns: Line separated list of rules.
        """

        filters = {'account': account}
        for k, v in request.args.items():
            filters[k] = v

        try:
            data = ""
            for rule in list_replication_rules(filters=filters):
                data += dumps(rule, cls=APIEncoder) + '\n'
            return Response(data, content_type="application/x-json-stream")
        except RuleNotFound, e:
            return generate_http_error_flask(404, 'RuleNotFound', e.args[0][0])
        except Exception, e:
            print format_exc()
            return e, 500


class Usage1(MethodView):

    def get(self, account):
        """
        Return the account usage of the account.

        .. :quickref: Usage1; Get account usage.

        :param account: The account name.
        :resheader Content-Type: application/x-json-stream
        :status 200: OK.
        :status 401: Invalid auth token.
        :status 404: Account not found.
        :status 500: Database exception.
        :returns: Line separated list of account usages.
        """

        try:
            data = ""
            for usage in get_account_usage(account=account, rse=None, issuer=request.environ.get('issuer')):
                data += dumps(usage, cls=APIEncoder) + '\n'
            return Response(data, content_type="application/x-json-stream")
        except AccountNotFound, e:
            return generate_http_error_flask(404, 'AccountNotFound', e.args[0][0])
        except AccessDenied, e:
            return generate_http_error_flask(401, 'AccessDenied', e.args[0][0])
        except Exception, e:
            print format_exc()
            return e, 500


class Usage2(MethodView):

    def get(self, account, rse):
        """
        Return the account usage of the account.

        .. :quickref: Usage2; Get account usage for RSE.

        :param account: The account name.
        :param rse: The rse.
        :resheader Content-Type: application/x-json-stream
        :status 200: OK.
        :status 401: Invalid auth token.
        :status 404: Account not found.
        :status 404: RSE not found.
        :status 500: Database exception.
        :returns: Line separated list of account usages.
        """
        try:
            data = ""
            for usage in get_account_usage(account=account, rse=rse, issuer=request.environ.get('issuer')):
                data += dumps(usage, cls=APIEncoder) + '\n'
            return Response(data, content_type="application/x-json-stream")
        except AccountNotFound, e:
            return generate_http_error_flask(404, 'AccountNotFound', e.args[0][0])
        except RSENotFound, e:
            return generate_http_error_flask(404, 'RSENotFound', e.args[0][0])
        except AccessDenied, e:
            return generate_http_error_flask(401, 'AccessDenied', e.args[0][0])
        except Exception, e:
            print format_exc()
            return e, 500


"""----------------------
   Web service startup
----------------------"""

bp = Blueprint('account', __name__)

attributes_view = Attributes.as_view('attributes')
bp.add_url_rule('/<account>/attr', view_func=attributes_view, methods=['get', ])
bp.add_url_rule('/<account>/attr/<key>', view_func=attributes_view, methods=['post', 'delete'])
scopes_view = Scopes.as_view('scopes')
bp.add_url_rule('/<account>/scopes', view_func=scopes_view, methods=['get', ])
bp.add_url_rule('/<account>/scopes/<scope>', view_func=scopes_view, methods=['post', ])
account_parameter_view = AccountParameter.as_view('account_parameter')
bp.add_url_rule('/<account>', view_func=account_parameter_view, methods=['get', 'put', 'post', 'delete'])
account_view = Account.as_view('account')
bp.add_url_rule('/', view_func=account_view, methods=['get', ])
account_limits_view = AccountLimits.as_view('account_limit')
bp.add_url_rule('/<account>/limits', view_func=account_limits_view, methods=['get', ])
bp.add_url_rule('/<account>/limits/<rse>', view_func=account_limits_view, methods=['get', ])
identities_view = Identities.as_view('identities')
bp.add_url_rule('/<account>/identities', view_func=identities_view, methods=['get', 'post', 'delete'])
rules_view = Rules.as_view('rules')
bp.add_url_rule('/<account>/rules', view_func=rules_view, methods=['get', ])
usage1_view = Usage1.as_view('usage1')
bp.add_url_rule('/<account>/usage', view_func=usage1_view, methods=['get', ])
usage2_view = Usage2.as_view('usage2')
bp.add_url_rule('/<account>/usage/<rse>', view_func=usage2_view, methods=['get', ])

application = Flask(__name__)
application.register_blueprint(bp)
application.before_request(before_request)
application.after_request(after_request)


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(bp, url_prefix='/accounts')
    return doc_app


if __name__ == "__main__":
    application.run()
