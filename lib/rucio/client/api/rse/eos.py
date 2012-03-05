"""
Copyright 2007-2011 European Organization for Nuclear Research (CERN)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.

You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Authors:
- Angelos Molfetas <angelos.molfetas@cern.ch> CERN PH/ADP, 2012-2012
"""

from subprocess import Popen, PIPE
from parent import Store, STATUS


class EosStorage(Store):
    """ EOS Store Interface Class """
    def __init__(self, server=None):
        #super(EosStorage,self).__init__()
        pass

    def listFilesInDir(self, dir):
        """ Lists file in specified directory at remote storage system"""
        try:
            process = Popen(['eos', 'ls', dir], shell=False, stdout=PIPE)
            output = process.communicate()
        except OSError, err:
            if 'No such file or directory' == err.strerror:
                output = process.communicate()
                status = STATUS.NOTFOUND
            else:
                status = STATUS.UNKNOWNERROR
        else:
            status = STATUS.DONE

        return (status, output)
