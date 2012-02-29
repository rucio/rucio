"""
Copyright 2007-2011 European Organization for Nuclear Research (CERN) 

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.

You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Authors:
- Angelos Molfetas <angelos.molfetas@cern.ch> CERN PH/ADP, 2012-2012
""" 

class STATUS:
    NOTFOUND = 0     # No such file or directory error
    UNKNOWNERROR = 1 # Don't know what happened
    DONE = 2         # No problem

class Store:
    """ Base class for storage interface"""
    def __init__(self, server = None):
        if server:
            self.server = server

    def listFilesInDir(self, server):
        pass
     
