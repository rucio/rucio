# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012

# To generate documentation:
#    nosetests --nocapture lib/rucio/tests/test_admin_demo.py > doc/source/cli_admin_examples.rst; python setup.py build_sphinx


from os import remove

from rucio.common.config import config_get
from rucio.tests.common import execute


class TestRucioDemo:

    @classmethod
    def setupClass(cls):
        try:
            remove('/tmp/.rucio_root/auth_token_root')
        except OSError, e:
            if e.args[0] != 2:
                raise e
        cmd = 'rm -rf /tmp/download/*'
        exitcode, out, err = execute(cmd)
        cmd = 'rm -rf /tmp/rucio_rse/*/'
        exitcode, out, err = execute(cmd)

    @classmethod
    def tearDownClass(cls):
        pass

    def setup(self):
        self.marker = '   $> '
        self.host = config_get('client', 'rucio_host')
        self.auth_host = config_get('client', 'auth_host')

    def test_rucio_demo(self):
        """ CLI(DEMO): Test the rucio admin demo """

        cmd = 'source /afs/cern.ch/atlas/offline/external/GRID/ddm/rucio/testing/bin/activate'
        cmd = 'cat /afs/cern.ch/atlas/offline/external/GRID/ddm/rucio/testing/etc/rucio.cfg'
        cmd = 'curl -s -X GET %s/ping' % self.host
        cmd = 'curl -s -X GET https://atlas-rucio.cern.ch/ping'

        cmd = 'rucio ping'
        # print self.marker + cmd
        exitcode, out, err = execute(cmd)
        # print out

        cmd = 'rucio whoami'
        # print self.marker + cmd
        exitcode, out, err = execute(cmd)
        # print out
        header = '''..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

========================
Rucio Admin CLI Examples
========================

The syntax of the Rucio admin command line interface is: rucio-admin <ressource> <command> [args], where ressource can be account,identity,rse,scope,meta.

The --help argument can be used to know the syntax of each commands.


Account
^^^^^^^'''
        print header

        print '``rucio-admin account add``'
        print '---------------------------'
        print 'Add an account::\n'
        cmd = 'rucio-admin account add vgaronne'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print '   ' + out

        print '``rucio-admin account del``'
        print '---------------------------'
        print 'Delete an account::\n'
        cmd = 'rucio-admin account del vgaronne'
        print self.marker + cmd
        #exitcode, out, err = execute(cmd)
        print '   Deleted account: vgaronne'

        print '``rucio-admin account list``'
        print '----------------------------'
        print 'List accounts::\n'
        cmd = 'rucio-admin account list'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        for l in out.split():
            print '   ' + l

        print '``rucio-admin account show``'
        print '----------------------------'
        print 'List account details::\n'
        cmd = 'rucio-admin account show vgaronne'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        for l in out.split('\n'):
            print '   ' + l

        print '``rucio-admin account set-limits``'
        print '----------------------------------'
        print 'Set account limits::\n'
        cmd = 'rucio-admin account set-limits --account vgaronne --rse_expr "GROUPDISK AND tier=1" --value 1000000'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        for l in out.split('\n'):
            print '   ' + l

        print '``rucio-admin account get-limits``'
        print '----------------------------------'
        print 'Get account limits::\n'
        cmd = 'rucio-admin account get-limits vgaronne'
        print self.marker + cmd

        print '``rucio-admin account del-limits``'
        print '----------------------------------'
        print 'Del account limits::\n'
        cmd = 'rucio-admin account del-limits --account vgaronne --rse_expr "GROUPDISK AND tier=1"'
        print self.marker + cmd

        print 'Identity'
        print '^^^^^^^^'

        print '``rucio-admin identity add``'
        print '----------------------------'
        print 'Grant a {userpass|x509|gss|proxy} identity access to an account::\n'
        cmd = 'rucio-admin identity add --account vgaronne --id vgaronne@CERN.CH --type gss'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print '   ' + out

        print '``rucio-admin list-identities``'
        print '-------------------------------'
        print 'List all identities on an account::\n'
        cmd = 'rucio-admin account list-identities vgaronne'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print '   ' + out

        print 'Rucio Storage Element (RSE)'
        print '^^^^^^^^^^^^^^^^^^^^^^^^^^^'

        print '``rucio-admin rse add``'
        print '-----------------------'
        print 'Add a RSE::\n'
        cmd = 'rucio-admin rse add MOCK'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print '   ' + out

        cmd = 'rucio-admin rse add MOCK1'
        exitcode, out, err = execute(cmd)
        cmd = 'rucio-admin rse add MOCK2'
        exitcode, out, err = execute(cmd)

        print '``rucio-admin rse list``'
        print '------------------------'
        print 'List RSEs::\n'
        cmd = 'rucio-admin rse list'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        for l in out.split('\n'):
            print '   ' + l

        print '``rucio-admin rse set-attr``'
        print '----------------------------'
        print 'Set RSE attribute::\n'
        cmd = 'rucio-admin rse set-attr --rse MOCK --key tier  --value 1'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        for l in out.split('\n'):
            print '   ' + l
        print 'Set RSE a tag (attribute with value=True)::\n'
        cmd = 'rucio-admin rse set-attr --rse MOCK2 --key GROUPDISK  --value True'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print '   ' + out

        print '``rucio-admin rse get-attr``'
        print '----------------------------'
        print 'Get RSE attribute::\n'
        cmd = 'rucio-admin rse get-attr MOCK'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        for l in out.split('\n'):
            print '   ' + l

        cmd = 'rucio-admin rse set-attr --rse MOCK2 --key CLOUD  --value CERN'
        exitcode, out, err = execute(cmd)

        print '``rucio-admin rse del-attr``'
        print '----------------------------'
        print 'Delete RSE attribute::\n'
        cmd = 'rucio-admin rse del-attr --rse MOCK2 --key CLOUD --value CERN'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        for l in out.split('\n'):
            print '   ' + l

        print 'Scope'
        print '^^^^^'

        print '``rucio-admin scope add``'
        print '-------------------------'
        print 'Add scope to an account::\n'
        cmd = 'rucio-admin scope add --account vgaronne --scope vgaronne'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        for l in out.split('\n'):
            print '   ' + l

        print '``rucio-admin scope list``'
        print '--------------------------'
        print 'List scopes::\n'
        cmd = 'rucio-admin scope list'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        for l in out.split('\n'):
            print '   ' + l

        print 'Meta-data'
        print '^^^^^^^^^'

        print '``rucio-admin meta add``'
        print '----------------------------'
        print 'Create a new allowed key(with default values if specified)::\n'
        cmd = 'rucio-admin meta add project'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        for l in out.split('\n'):
            print '   ' + l

        print '``rucio-admin meta del``'
        print '----------------------------'
        print 'Delete an allowed key or key/value::\n'
        cmd = 'rucio-admin metadata del --key --value --type --DItypes'
        print self.marker + cmd

        print '``rucio-admin meta list``'
        print '-----------------------------'
        print 'List all allowed keys with their default values::\n'
        cmd = 'rucio-admin meta list'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        for l in out.split('\n'):
            print '   ' + l

        print '``rucio-admin meta add_value``'
        print '-----------------------------'
        print 'Create a new allowed value for a key::\n'
        cmd = 'rucio-admin meta add_value --key=project --value=data12'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        for l in out.split('\n'):
            print '   ' + l

        print '``rucio-admin meta list_values``'
        print '-----------------------------'
        print 'List all allowed values for a key::\n'
        cmd = 'rucio-admin meta list_values project'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        for l in out.split('\n'):
            print '   ' + l
