# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012


"""
Client class for callers of the Rucio system
"""

import os
import requests

from rucio.common.exception import CannotAuthenticate
from rucio.common.exception import NoAuthInformation
from rucio.common.exception import RucioException
from rucio.common.utils import build_url


class Client(object):

    """Main client class for accessing Rucio resources. Handles the authentication."""

    TOKEN_PATH = '/tmp/rucio'
    TOKEN_PREFIX = 'auth_token_'

    def __init__(self, host, port=None, account=None, use_ssl=False, auth_type=None, creds=None, debug=False):
        self.host = host
        self.port = port
        self.account = account
        self.use_ssl = use_ssl
        self.auth_type = auth_type
        self.creds = creds
        self.auth_token = None
        self.debug = debug

        if auth_type is None or creds is None:
            raise NoAuthInformation('No auth type or credentials specified')

        if account is None:
            raise NoAuthInformation('no account name specified')

        if auth_type == 'userpass':
            self.__auth_userpass(creds)
        else:
            raise CannotAuthenticate('auth type \'%s\' no supported' % auth_type)

    def __debug(self, message):
        """
        helper method to print debug messages if self.debug is set to True.

        :param message: string message to print.
        """

        if self.debug:
            print('DEBUG: ' + message)

    def __get_token_userpass(self, username, password):
        """
        sends a request to get an auth token from the server. Uses username/password. For testing only.

        :param username: the username to authenticate with the system.
        :param password: the password to authenticate with the system.
        :return: the auth token as a string, None if not authorized or raises an exeption if some failure occurs.
        """

        headers = {'Rucio-Account': self.account, 'Rucio-Username': username, 'Rucio-Password': password}
        url = build_url(self.host, path='auth/userpass')
        r = requests.get(url, headers=headers)

        if r.status_code == requests.codes.unauthorized:
            return None
        if r.status_code != requests.codes.ok:
            raise RucioException('unknown error')

        auth_token = r.headers['rucio-auth-token']
        return auth_token

    def __check_token(self):
        """
        sends a request to check if the given token is valid.

        :return: True if token is valid. False otherwise.
        """

        headers = {'Rucio-Account': self.account, 'Rucio-Auth-Token': self.auth_token}
        url = build_url(self.host, path='auth/validate')
        r = requests.get(url, headers=headers)

        if r.status_code == requests.codes.unauthorized:
            return False
        if r.status_code != requests.codes.ok:
            raise RucioException("unknown error")

        return True

    def __auth_userpass(self, creds):
        """
        does the authentication with username / password. Either creates a new token file if none is already existing for the account or reads an existing token file, checks the token and gets a new one if not valid anymore.

        :param creds: dictionary containing 'username' and 'password' credentials.
        """

        if creds['username'] is None or creds['password'] is None:
            raise NoAuthInformation('No username or password passed')

        username = creds['username']
        password = creds['password']

        self.token_file = self.TOKEN_PATH + '/' + self.TOKEN_PREFIX + self.account
        self.token_file = '/tmp/rucio/auth_token_' + self.account

        # check if rucio temp directory is there. If not create it with permissions only for the current user
        if not os.path.isdir(self.TOKEN_PATH):
            try:
                self.__debug('rucio token folder \'%s\' not found. Create it.' % self.TOKEN_PATH)
                os.mkdir(self.TOKEN_PATH, 0700)
            except Exception, e:
                raise e

        # check if there is already a token file. If not get a new token from the server, create the file with permission only for the current user and save the token.
        if not os.path.exists(self.token_file):
            self.__debug('token file \'%s\' doesnt exist. Request token.' % self.token_file)
            self.auth_token = self.__get_token_userpass(username, password)
            if self.auth_token is None:
                raise CannotAuthenticate('wrong credentials')
            try:
                self.__debug('Got token \'%s\'' % self.auth_token)
                self.__debug('Create new token file \'%s\' and write token' % self.token_file)
                token_file_handler = open(self.token_file, 'w')
                token_file_handler.write(self.auth_token)
                token_file_handler.close()
                os.chmod(self.token_file, 0700)
            except IOError as (errno, strerror):
                print("I/O error({0}): {1}".format(errno, strerror))
            except Exception, e:
                raise e
        # if the file exists check if the stored token is valid. If not request a new one and overwrite the file. Otherwise use the one from the file
        else:
            self.__debug('token file \'%s\' found' % self.token_file)
            try:
                token_file_handler = open(self.token_file, 'r+w')
                self.auth_token = token_file_handler.readline()
                self.__debug('check token \'%s\'' % self.auth_token)
                if not self.__check_token():
                    self.__debug('token \'%s\' not valid get a new one' % self.auth_token)
                    self.auth_token = self.__get_token_userpass(username, password)
                    if self.auth_token is None:
                        raise CannotAuthenticate('wrong credentials')
                    self.__debug('overwrite old token in file with new one \'%s\'' % self.auth_token)
                    token_file_handler.seek(0)
                    token_file_handler.write(self.auth_token)
                self.__debug('token valid.')
                token_file_handler.close()
            except IOError as (errno, strerror):
                print("I/O error({0}): {1}".format(errno, strerror))
            except Exception, e:
                raise
