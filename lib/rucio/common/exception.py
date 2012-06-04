# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch> , 2012
# - Angelos Molfetas, <angelos.molfetas@cern,ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012


class RucioException(Exception):
    """
    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.
    """

    def __init__(self, *args, **kwargs):
        self._message = "An unknown exception occurred"
        self.args = args
        self.kwargs = kwargs

    def __str__(self):
        try:
            self._error_string = self._message % self.kwargs
        except Exception:
            # at least get the core message out if something happened
            self._error_string = self._message
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
        super(AccountNotFound, self).__init__(args, kwargs)
        self._message = "Account does not exist."


class ScopeNotFound(RucioException):
    def __init__(self, *args, **kwargs):
        super(ScopeNotFound, self).__init__(args, kwargs)
        self._message = "Scope does not exist."


class NoPermisions(RucioException):
    def __init__(self, *args, **kwargs):
        super(NoPermisions, self).__init__(args, kwargs)
        self._message = "User does not have necessary permissions to perform operation."


class NotADataset(RucioException):
    def __init__(self, *args, **kwargs):
        super(NotADataset, self).__init__(args, kwargs)
        self._message = 'Specified inode is not a dataset'


class NotAFile(RucioException):
    def __init__(self, *args, **kwargs):
        super(NotAFile, self).__init__(args, kwargs)
        self._message = 'Specified inode is not a file'


class DatasetAlreadyExists(RucioException):
    def __init__(self, *args, **kwargs):
        super(DatasetAlreadyExists, self).__init__(args, kwargs)
        self._message = "Dataset name in specified scope already exists"


class FileAlreadyExists(RucioException):
    def __init__(self, *args, **kwargs):
        super(FileAlreadyExists, self).__init__(args, kwargs)
        self._message = "File name in specified scope already exists"


class DatasetNotFound(RucioException):
    def __init__(self, *args, **kwargs):
        super(DatasetNotFound, self).__init__(args, kwargs)
        self._message = "Dataset not found in scope"


class DatasetObsolete(RucioException):
    def __init__(self, *args, **kwargs):
        super(DatasetObsolete, self).__init__(args, kwargs)
        self._message = "Dataset is obsolete"


class FileNotFound(RucioException):
    def __init__(self, *args, **kwargs):
        super(FileNotFound, self).__init__(args, kwargs)
        self._message = "File not found in scope"


class InodeTypeError(RucioException):
    def __init__(self, *args, **kwargs):
        super(InodeTypeError, self).__init__(args, kwargs)
        self._message = "Inode is of the wrong type"


class ForbiddenSearch(RucioException):
    def __init__(self, *args, **kwargs):
        super(ForbiddenSearch, self).__init__(args, kwargs)
        self._message = "Wildcard search too broad"


class Duplicate(RucioException):
    def __init__(self, *args, **kwargs):
        super(Duplicate, self).__init__()
        self._message = "An object with the same identifier already exists."


class NoAuthInformation(RucioException):
    def __init__(self, *args, **kwargs):
        super(NoAuthInformation, self).__init__()
        self._message = "No authentication information passed."


class CannotAuthenticate(RucioException):
    def __init__(self, *args, **kwargs):
        super(CannotAuthenticate, self).__init__()
        self._message = "Cannot authenticate."


class IdentityError(RucioException):
    def __init__(self, *args, **kwargs):
        super(IdentityError, self).__init__()
        self._message = "Identity error."
