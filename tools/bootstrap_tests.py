#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
# - Martin Barisits, <martin.barisits@cern.ch>, 2017
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2017

from rucio.client import Client
from rucio.common.exception import Duplicate
from rucio.core.account import add_account_attribute


if __name__ == '__main__':
    c = Client()
    try:
        c.add_account('jdoe', 'SERVICE', 'jdoe@email.com')
    except Duplicate:
        print 'Account jdoe already added' % locals()

    try:
        add_account_attribute(account='root', key='admin', value=True)
    except Exception, e:
        print e

    try:
        c.add_account('panda', 'SERVICE', 'panda@email.com')
        add_account_attribute(account='panda', key='admin', value=True)
    except Duplicate:
        print 'Account panda already added' % locals()

    try:
        c.add_scope('jdoe', 'mock')
    except Duplicate:
        print 'Scope mock already added' % locals()

    try:
        c.add_scope('root', 'archive')
    except Duplicate:
        print 'Scope archive already added' % locals()

    # add your accounts here, if you test against CERN authed nodes
    additional_test_accounts = [('/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=mlassnig/CN=663551/CN=Mario Lassnig', 'x509', 'mario.lassnig@cern.ch'),
                                ('/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=barisits/CN=692443/CN=Martin Barisits', 'x509', 'martin.barisits@cern.ch'),
                                ('/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=tbeerman/CN=722011/CN=Thomas Beermann', 'x509', 'thomas.beermann@cern.ch'),
                                ('/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=ruciobuildbot/CN=692443/CN=Robot: Rucio build bot', 'x509', 'rucio.build.bot@cern.ch'),
                                ('/CN=docker client', 'x509', 'dummy@cern.ch'),
                                ('mlassnig@CERN.CH', 'GSS', 'mario.lassnig@cern.ch')]

    for i in additional_test_accounts:
        try:
            c.add_identity(account='root', identity=i[0], authtype=i[1], email=i[2])
        except:
            print 'Already added: ', i
