# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne,  <vincent.garonne@cern.ch>, 2013

from rucio.common import exception
from rucio.common.config import config_get
from rucio.db import session, migration
from rucio.db import models


def build_database(echo=True):
    """ Applies the schema to the database. Run this command once to build the database. """
    engine = session.get_engine(echo=echo)
    models.register_models(engine)
    try:
        sql_connection = config_get('database', 'default')
        migration.version_control(sql_connection=sql_connection)
    except exception.DatabaseMigrationError:
        # Can happen if the DB exists and is under version control
        pass


def destroy_database(echo=True):
    """ Removes the schema from the database. Only useful for test cases or malicious intents. """

    engine = session.get_engine(echo=echo)
    models.unregister_models(engine)


def create_root_account():
    """ Inserts the default root account to an existing database. Make sure to change the default password later. """

    up_id = 'ddmlab'
    up_pwd = '2ccee6f6dd1bc2269cddd7cd5e47578e98e430539807c36df23fab7dd13e7583'
    up_email = 'ph-adp-ddm-lab@cern.ch'
    x509_id = '/C=CH/ST=Geneva/O=CERN/OU=PH-ADP-CO/CN=DDMLAB Client Certificate/emailAddress=ph-adp-ddm-lab@cern.ch'
    x509_email = 'ph-adp-ddm-lab@cern.ch'
    gss_id = 'ddmlab@CERN.CH'
    gss_email = 'ph-adp-ddm-lab@cern.ch'

    try:
        up_id = config_get('bootstrap', 'userpass_identity')
        up_pwd = config_get('bootstrap', 'userpass_pwd')
        up_email = config_get('bootstrap', 'userpass_email')
        x509_id = config_get('bootstrap', 'x509_identity')
        x509_email = config_get('bootstrap', 'x509_email')
        gss_id = config_get('bootstrap', 'gss_identity')
        gss_email = config_get('bootstrap', 'gss_email')
    except:
        pass
        # print 'Config values are missing (check rucio.cfg{.template}). Using hardcoded defaults.'

    s = session.get_session()

    account = models.Account(account='root', type='user', status='active')

    identity1 = models.Identity(identity=up_id, type='userpass', password=up_pwd, salt='0', email=up_email)
    iaa1 = models.IdentityAccountAssociation(identity=identity1.identity, type=identity1.type, account=account.account, is_default=True)

    # X509 authentication
    identity2 = models.Identity(identity=x509_id, type='x509', email=x509_email)
    iaa2 = models.IdentityAccountAssociation(identity=identity2.identity, type=identity2.type, account=account.account, is_default=True)

    # GSS authentication
    identity3 = models.Identity(identity=gss_id, type='gss', email=gss_email)
    iaa3 = models.IdentityAccountAssociation(identity=identity3.identity, type=identity3.type, account=account.account, is_default=True)

    # Apply
    s.add_all([account, identity1, identity2, identity3])
    s.commit()
    s.add_all([iaa1, iaa2, iaa3])
    s.commit()
