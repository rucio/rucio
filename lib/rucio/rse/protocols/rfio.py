# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013

import os

from os.path import dirname, normpath

from rucio.common.utils import execute
from rucio.rse.protocols import protocol


class Default(protocol.RSEProtocol):

    def __init__(self, props):
        self.rse = props

    def connect(self, credentials):
        extended_attributes = self.rse['protocol']['extended_attributes']
        if 'STAGE_SVCCLASS' in extended_attributes:
            os.environ['STAGE_SVCCLASS'] = extended_attributes['STAGE_SVCCLASS']

    def pfn2uri(self, pfn):
        path = self.rse['prefix'] + '/' + pfn    # NOQA
        return normpath(path)

    def exists(self, pfn):
        path = self.pfn2uri(pfn)    # NOQA
        cmd = 'rfstat %(path)s' % locals()
        status, out, err = execute(cmd)
        return status == 0

    def close(self):
        if 'STAGE_SVCCLASS' in os.environ:
            del os.environ['STAGE_SVCCLASS']

    def get(self, pfn, dest):
        raise NotImplemented

    def put(self, source, target, source_dir):
        path = self.pfn2uri(target)    # NOQA
        # Check
        if not self.exists(dirname(target)):
            self.mkdir(dirname(target))

        cmd = 'rfcp %(source)s %(path)s' % locals()
        print cmd
        status, out, err = execute(cmd)
        return status == 0

    def mkdir(self, directory):
        path = self.pfn2uri(directory)  # NOQA
        cmd = 'rfmkdir -p %(path)s' % locals()
        status, out, err = execute(cmd)
        return status == 0

    def delete(self, pfn):
        #cmd = 'rfrm %(path)s' % locals()
        #print cmd
        # status, out, err  = execute(cmd)
        raise NotImplemented

    def rename(self, lfn, new_lfn):
        raise NotImplemented
