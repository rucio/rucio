# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012

import rucio.core.authentication


def get_auth_token_user_pass(account, username, password, ip=None):
    """Authenticate a Rucio account temporarily via username and password.

    The tokens initial lifetime is 1 hour.

    :param account: Account identifier.
    :param username: Username as a string.
    :param password: SHA1 hash of the password as a string.
    :param ip: IP address of the client
    :returns: Authentication token as a 32 character hex string."""
    return rucio.core.authentication.get_auth_token_user_pass(account, username, password, ip)


def get_auth_token_kerberos(account, credential):
    """Authenticate a Rucio account temporarily via a Kerberos token.

    The tokens initial lifetime is 1 hour.

    :param account: Account identifier.
    :param credential: Kerberos GSSAPI token credential location.
    :returns: Authentication token as a 32 character hex string."""
    raise NotImplementedError


def get_auth_token_x509(account, certificate):
    """Authenticate a Rucio account temporarily via an x509 certificate.

    The tokens initial lifetime is 1 hour.

    :param account: Account identifier.
    :param credential: x509 certificate location.
    :returns: Authentication token as a 32 character hex string."""
    raise NotImplementedError


def validate_auth_token(account, token):
    """Validate an authentication token.

    If the validation is successful, the token lifetime will be extended by 1 hour.

    :param account: Account identifier.
    :param token: Authentication token as a 32 character hex string.
    :returns: true, if the token is valid and was extended, false otherwise"""
    return rucio.core.authentication.validate_auth_token(account, token)


def register_api_token(account, responsible, service_name):
    """Register a new service with a unique, permanent API token.

    :param account: Account identifier.
    :param responsible: Email address of the service responsible as a string.
    :param service_name: Name of the service as a string.
    :returns: API token as an 32 character hex string."""
    raise NotImplementedError


def validate_api_token(account, token):
    """Validate an API token.

    :param account: Account identifier.
    :param token: API token as a 32 character hex string."""
    raise NotImplementedError
