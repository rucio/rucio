# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

from os import remove

from rucio.db.session import build_database, destroy_database, create_root_account
from rucio.tests.common import execute


class TestRucioDemo:

    @classmethod
    def setUpClass(cls):
        destroy_database(echo=False)
        build_database(echo=False)
        create_root_account()
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
        #destroy_database(echo=False)

    def setUp(self):
        self.marker = '$> '

    def test_rucio_demo(self):
        """ CLI(DEMO): Test the rucio demo """

        cmd = 'source /afs/cern.ch/atlas/offline/external/GRID/ddm/rucio/testing/bin/activate'
        cmd = 'cat /afs/cern.ch/atlas/offline/external/GRID/ddm/rucio/testing/etc/rucio.cfg'
        cmd = 'curl -s  -X GET http://localhost/ping'
        cmd = 'curl -s -X GET http://atlas-rucio.cern.ch/ping'

        cmd = 'rucio ping'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio whoami'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio-admin account add vgaronne'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio-admin identity add  --account vgaronne --id vgaronne@CERN.CH --type gss'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = "rucio-admin identity add  --account vgaronne --id '/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=vgaronne/CN=614522/CN=Vincent Garonne' --type x509"
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio-admin account list-identities vgaronne'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio-admin scope add --account vgaronne --scope vgaronne'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio-admin account list'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio-admin account show vgaronne'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio-admin rse add MOCK'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio-admin rse add MOCK1'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio-admin rse add MOCK2'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio-admin rse list'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio-admin rse set-attr --rse MOCK --key tier  --value 1'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio-admin rse get-attr MOCK'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio-admin rse set-attr --rse MOCK2 --key CLOUD  --value CERN'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio-admin rse set-attr --rse MOCK2 --key GROUPDISK  --value True'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out
        cmd = 'rucio-admin rse del-attr --rse MOCK2 --key CLOUD --value CERN'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio-admin rse get-attr MOCK2'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio-admin account set-limits --account vgaronne --rse_expr "GROUPDISK AND tier=1" --value 1000000'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio-admin scope list'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio add-replicas  --lfns vgaronne:Myfile vgaronne:Myfile1 vgaronne:Myfile2 --rses MOCK1 MOCK1 MOCK1 --checksums ad:92ce22ac ad:92ce22ab ad:92ce22ac  --sizes 2849063278 2849063277 2849063279'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio list-replicas vgaronne:Myfile'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio add --dest vgaronne:MyDataset1 --srcs vgaronne:Myfile vgaronne:Myfile1'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio add --dest vgaronne:MyDataset2 --srcs vgaronne:Myfile2'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio add --dest vgaronne:MyContainer1 --srcs vgaronne:MyDataset1 vgaronne:MyDataset2'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio add --dest vgaronne:MyBigContainer1 --srcs vgaronne:MyContainer1'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio list vgaronne:MyBigContainer1'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio list vgaronne:MyContainer1'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio list vgaronne:MyDataset1'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio list-files vgaronne:MyDataset1'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio list-files vgaronne:MyBigContainer1'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio list-replicas vgaronne:MyBigContainer1'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio upload --rse MOCK --scope vgaronne --files Myfile4'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'ls /tmp/download/vgaronne/'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio download --dir=/tmp/download  vgaronne:Myfile4'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'ls /tmp/download/vgaronne/'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio-admin rse add swift.cern.ch'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 's3cmd mb s3://RSETESTS3'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio upload --rse swift.cern.ch  --scope vgaronne --files Myfile5'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio download --dir=/tmp/download  vgaronne:Myfile5'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'ls /tmp/download/vgaronne/'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 's3cmd ls  s3://RSETESTS3'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 's3cmd ls  s3://RSETESTS3/vgaronne'
        print self.marker + cmd
        exitcode, out, err = execute(cmd)
        print out

        cmd = 'rucio del vgaronne:MyDataset1 --from vgaronne:MyContainer1'
        cmd = 'rucio del vgaronne:MyDataset1'

        # Meta-data
        cmd = 'rucio search'
        cmd = 'rucio-admin metadata add --key --value --type --DItypes'
        cmd = 'rucio-admin metadata del --key --value --type --DItypes'
        cmd = 'rucio-admin metadata list --filters'
        cmd = 'rucio get-metadata'
        cmd = 'rucio set-metadata'
        cmd = 'rucio del-metadata'

        cmd = 'rucio-admin account set-limits --account ddd --rse_expr --value'
        cmd = 'rucio-admin account get-limits account'
        cmd = 'rucio-admin account del-limits --account ddd --rse_expr'

        cmd = 'rucio list-rse-usage --history'
        cmd = 'rucio list-account-usage --history'
        cmd = 'rucio list-account-limits'

        cmd = 'rucio close vgaronne:MyDataset1'
