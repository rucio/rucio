# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012
# - Vincent Garonne,  <vincent.garonne@cern.ch> , 2011-2013

from rucio.api import permission
from rucio.common import exception
from rucio.core import authentication


def get_auth_token_user_pass(account, username, password, ip=None):
    """Authenticate a Rucio account temporarily via username and password.

    The tokens initial lifetime is 1 hour.

    :param account: Account identifier.
    :param username: Username as a string.
    :param password: SHA1 hash of the password as a string.
    :param ip: IP address of the client.
    :returns: Authentication token as a 32 character hex string."""

    kwargs = {'account': account, 'username': username, 'password': password}
    if not permission.has_permission(issuer=account, action='get_auth_token_user_pass', kwargs=kwargs):
        raise exception.AccessDenied('User with identity %s can not log to account %s' % (username, account))

    return authentication.get_auth_token_user_pass(account, username, password, ip)


def get_auth_token_gss(account, gsscred, ip=None):
    """Authenticate a Rucio account temporarily via a GSS token.

    The tokens initial lifetime is 1 hour.

    :param account: Account identifier.
    :param gsscred: GSS principal@REALM
    :param ip: IP address of the client.
    :returns: Authentication token as a 32 character hex string."""

    kwargs = {'account': account, 'gsscred': gsscred}
    if not permission.has_permission(issuer=account, action='get_auth_token_gss', kwargs=kwargs):
        raise exception.AccessDenied('User with identity %s can not log to account %s' % (gsscred, account))

    return authentication.get_auth_token_gss(account, gsscred, ip)


def get_auth_token_x509(account, dn, ip=None):
    """Authenticate a Rucio account temporarily via an x509 certificate.

    The tokens initial lifetime is 1 hour.

    :param account: Account identifier.
    :param dn: Client certificate distinguished name string, as extracted by Apache/mod_ssl.
    :param ip: IP address of the client.
    :returns: Authentication token as a 32 character hex string."""

    kwargs = {'account': account, 'dn': dn}
    if not permission.has_permission(issuer=account, action='get_auth_token_x509', kwargs=kwargs):
        raise exception.AccessDenied('User with identity %s can not log to account %s' % (dn, account))

    return authentication.get_auth_token_x509(account, dn, ip)


def validate_auth_token(token):
    """Validate an authentication token.

    If the validation is successful, the token lifetime will be extended by 1 hour.

    :param account: Account identifier.
    :param token: Authentication token as a 32 character hex string.
    :returns: Tuple(account name, Datetime(expected expiry time)) if successful, None otherwise."""
    return authentication.validate_auth_token(token)
