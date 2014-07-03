#!/usr/bin/env python

# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Cheng-Hsi Chao, <cheng-hsi.chaos@cern.ch>, 2014

"""
Script to sync LDAP accounts as Rucio Identity
"""

import ConfigParser
import getpass
import ldap
import ldapurl
import os
from rucio.client import Client
from rucio.common import exception
import re


def initiate_ldap():
    """
    contact the LDAP server to return a LDAP object
    """
    ldap_schemes = ['ldap://', 'ldaps://']
    ldap.set_option(ldap.OPT_DEBUG_LEVEL, 0)
    ldap.set_option(ldap.OPT_X_TLS_CACERTDIR, config.get('ldap', 'cacertdir'))
    ldap.set_option(ldap.OPT_X_TLS_CERTFILE, config.get('ldap', 'certfile'))
    ldap.set_option(ldap.OPT_X_TLS_KEYFILE, config.get('ldap', 'keyfile'))
    ldap.set_option(ldap.OPT_X_TLS_DEMAND, True)
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)  # TRY, NEVER, DEMAND
    ldap.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
    for scheme in ldap_schemes:
        ldap_url = scheme + server_url
        ldap_obj = ldap.initialize(ldap_url)
        try:
            ldap_obj.start_tls_s()
        except ldap.OPERATIONS_ERROR as e:
            e_msg = e[0]['info']
            if e_msg == 'TLS already started':
                pass
            else:
                raise
        except ldap.SERVER_DOWN:
            if scheme is not ldap_schemes[-1]:
                continue
            else:
                raise
        if login_dn != 'DEFAULT':  # Use anonymous bind if login_dn is set as DEFAULT
            ldap_obj.bind(login_dn, password, ldap.AUTH_SIMPLE)
        else:
            try:
                ldap_obj.whoami_s()
            except ldap.UNWILLING_TO_PERFORM:
                print 'Anonymous binding is disabled by server'
                raise SystemExit
        return ldap_obj
        break


def add_identity(ldapObject):
    """
    add LDAP entry as Rucio Identity
    """
    results = ldapObject.search_s(baseDN, searchScope, searchFilter, retrieveAttributes)
    for result in results:
        try:
            if 'account' in retrieveAttributes:
                account = result[1]['account'][0]
            else:
                account = result[1]['uid'][0]
            if not re.match(r'^[a-z0-9-_]{1,30}$', account):
                print 'account: \'' + account + '\' is invalid as Rucio account'
                continue
            if 'auth_type' in retrieveAttributes:
                authtype = result[1]['auth_type'][0]
            else:
                authtype = 'x509'  # Default authtype set as X509
            identity = result[1]['gecos'][0]
            email = result[1]['mail'][0]
            add_account(account)
            client.add_identity(account, identity, authtype, email)
            print 'Added new identity to account: %s-%s' % (identity, account)
        except KeyError as e:
            print 'Attribute', e, 'for account \'' + account + '\' is missing'
            continue
        except exception.Duplicate as e:
            print e[0][0]
            continue


def add_account(account):
    """
    add account for LDAP entry
    """
    type = 'USER'
    try:
        client.get_account(account)
        print 'Account \'' + account + '\' is already registered as Rucio account'
    except exception.AccountNotFound:
        client.add_account(account, type)
        pass
    except exception.InvalidObject as e:
        print e[0][0]
        pass

# Get LDAP Config
config = ConfigParser.ConfigParser()
configfiles = list()
if 'RUCIO_HOME' in os.environ:
    configfiles.append('%s/etc/ldap.cfg' % os.environ['RUCIO_HOME'])
configfiles.append('/opt/rucio/etc/ldap.cfg')

if 'VIRTUAL_ENV' in os.environ:
    configfiles.append('%s/etc/ldap.cfg' % os.environ['VIRTUAL_ENV'])
has_config = False
for configfile in configfiles:
    has_config = config.read(configfile) == [configfile]
    if has_config:
        break

# Global Variables
client = Client()
server_url = config.get('ldap', 'ldap_host')
baseDN = config.get('ldap', 'baseDN')
searchScope = ldapurl.LDAP_SCOPE_SUBTREE
retrieveAttributes = ['uid', 'gecos', 'mail']
if config.get('attributes', 'account') != 'uid':
    retrieveAttributes.append('account')
if config.get('attributes', 'auth_type') != 'DEFAULT':
    retrieveAttributes.append('auth_type')
searchFilter = config.get('ldap', 'searchFilter')
login_dn = config.get('ldap', 'login_dn')
if login_dn is 'DEFAULT':
    login_dn = None
password = config.get('ldap', 'password')
if not password and login_dn is not 'DEFAULT':  # Prompt for password if left blank using DN bind
    password = str(getpass.getpass("Please input LDAP LoginDN's password: "))

if __name__ == '__main__':
    add_identity(initiate_ldap())
