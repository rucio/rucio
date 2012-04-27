# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann,  <thomas.beermann@cern.ch> , 2012
# - Angelos Molfetas, <angelos.molfetas@cern,ch>, 2012


class RucioException(Exception):
    """
    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.
    """

    def __init__(self, *args, **kwargs):
        self.message = "An unknown exception occurred"
        self.args = args
        self.kwargs = kwargs

    def __str__(self):
        try:
            self._error_string = self.message % self.kwargs
        except Exception:
            # at least get the core message out if something happened
            self._error_string = self.message
        if len(self.args) > 0:
            # If there is a non-kwarg parameter, assume it's the error
            # message or reason description and tack it on to the end
            # of the exception message
            # Convert all arguments into their string representations...
            args = ["%s" % arg for arg in self.args]
            self._error_string = (self._error_string + "\nDetails: %s" % '\n'.join(args))
        return self._error_string


class AccountNotFound(RucioException):
    def __init__(self, *args, **kwargs):
        super(AccountNotFound, self).__init__()
        self.message = "Account does not exist."


class ScopeNotFound(RucioException):
    def __init__(self, msg):
        super(ScopeNotFound, self).__init__()
        self.message = "Scope does not exist."


class DatasetAlreadyExists(RucioException):
    def __init(self, msg):
        super(Duplicate, self).__init__()
        self.message = "Dataset name in specified scope already exists"


class Duplicate(RucioException):
    def __init__(self, msg):
        super(Duplicate, self).__init__()
        self.message = "An object with the same identifier already exists."
