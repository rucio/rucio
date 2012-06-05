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

import logging
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

    def __init__(self, host, port=None, account=None, use_ssl=False, auth_type=None, creds=None):
        self.host = host
        self.port = port
        self.account = account
        self.use_ssl = use_ssl
        self.auth_type = auth_type
        self.creds = creds
        self.auth_token = None

        if auth_type is None or creds is None:
            raise NoAuthInformation('No auth type or credentials specified')

        if account is None:
            raise NoAuthInformation('no account name specified')

        self.__authenticate()

    def _send_request(self, url, headers, type='GET', data=None, retries=3):
        """
        Helper method to send requests to the rucio server. Gets a new token and retries if an unauthorized error is returned.

        :param url: the http url to use.
        :param headers: http headers to send.
        :param type: the http request type to use.
        :param data: post data.
        :param retries: number of retries in case of unauthorized.
        :return: the HTTP return body.
        """

        r = None
        retry = 0
        while retry < retries:
            if type == 'GET':
                r = requests.get(url, headers=headers)
            elif type == 'POST':
                r = requests.post(url, headers=headers, data=data)
            elif type == 'DEL':
                r = requests.delete(url, headers=headers)
            else:
                return

            if r.status_code == requests.codes.unauthorized:
                self.__get_token()
                headers['Rucio-Auth-Token'] = self.auth_token
                retry += 1
            else:
                break

        return r

    def __get_token_userpass(self):
        """
        Sends a request to get an auth token from the server. Uses username/password.

        :param username: the username to authenticate with the system.
        :param password: the password to authenticate with the system.
        :return: the auth token as a string, None if not authorized or raises an exeption if some failure occurs.
        """

        headers = {'Rucio-Account': self.account, 'Rucio-Username': self.creds['username'], 'Rucio-Password': self.creds['password']}
        url = build_url(self.host, path='auth/userpass')
        r = requests.get(url, headers=headers)

        if r.status_code == requests.codes.unauthorized:
            raise CannotAuthenticate('wrong credentials')
        if r.status_code != requests.codes.ok:
            raise RucioException('unknown error')

        self.auth_token = r.headers['rucio-auth-token']
        logging.debug('got new token \'%s\'' % self.auth_token)

    def __get_token(self):
        """
        Sends a request to get a new token and write it to file. To be used if a 401 - Unauthorized error is received.
        """

        logging.debug('get a new token')
        if self.auth_type == 'userpass':
            self.__get_token_userpass()
        else:
            raise CannotAuthenticate('auth type \'%s\' no supported' % self.auth_type)

        self.__write_token()

    def __read_token(self):
        """
        Checks if a local token file exists and reads the token from it.

        :return: True if a token could be read. False if no file exists.
        """

        self.token_file = self.TOKEN_PATH + '/' + self.TOKEN_PREFIX + self.account
        self.token_file = '/tmp/rucio/auth_token_' + self.account

        if not os.path.exists(self.token_file):
            return False

        try:
            token_file_handler = open(self.token_file, 'r')
            self.auth_token = token_file_handler.readline()
        except IOError as (errno, strerror):
            print("I/O error({0}): {1}".format(errno, strerror))
        except Exception, e:
            raise e

        logging.debug('read token \'%s\' from file' % self.auth_token)
        return True

    def __write_token(self):
        """
        Write the current auth_token to the local token file.
        """

        self.token_file = self.TOKEN_PATH + '/' + self.TOKEN_PREFIX + self.account
        self.token_file = '/tmp/rucio/auth_token_' + self.account

        # check if rucio temp directory is there. If not create it with permissions only for the current user
        if not os.path.isdir(self.TOKEN_PATH):
            try:
                logging.debug('rucio token folder \'%s\' not found. Create it.' % self.TOKEN_PATH)
                os.mkdir(self.TOKEN_PATH, 0700)
            except Exception, e:
                raise e

        # if the file exists check if the stored token is valid. If not request a new one and overwrite the file. Otherwise use the one from the file
        try:
            token_file_handler = open(self.token_file, 'w')
            token_file_handler.write(self.auth_token)
            token_file_handler.close()
            os.chmod(self.token_file, 0700)
        except IOError as (errno, strerror):
            print("I/O error({0}): {1}".format(errno, strerror))
        except Exception, e:
            raise e

    def __authenticate(self):
        """
        Main method for authentication. It first tries to read a locally saved token. If not available it requests a new one.
        """

        if self.auth_type == 'userpass':
            if self.creds['username'] is None or self.creds['password'] is None:
                raise NoAuthInformation('No username or password passed')
        else:
            raise CannotAuthenticate('auth type \'%s\' no supported' % self.auth_type)

        if not self.__read_token():
            self.__get_token()
