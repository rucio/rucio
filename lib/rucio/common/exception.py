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
# - Vincent Garonne,  <vincent.garonne@cern.ch> , 2011


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
            args = ["%s" % arg for arg in self.args if arg]
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


class NoPermissions(RucioException):
    def __init__(self, *args, **kwargs):
        super(NoPermissions, self).__init__(args, kwargs)
        self._message = "User does not have necessary permissions to perform operation."


class NotADataset(RucioException):
    def __init__(self, *args, **kwargs):
        super(NotADataset, self).__init__(args, kwargs)
        self._message = 'Specified name is not a dataset'


class NotAFile(RucioException):
    def __init__(self, *args, **kwargs):
        super(NotAFile, self).__init__(args, kwargs)
        self._message = 'Specified name is not a file'


class DatasetAlreadyExists(RucioException):
    def __init__(self, *args, **kwargs):
        super(DatasetAlreadyExists, self).__init__(args, kwargs)
        self._message = "Dataset name in specified scope already exists"


class FileReplicaAlreadyExists(RucioException):
    def __init__(self, *args, **kwargs):
        super(FileReplicaAlreadyExists, self).__init__(args, kwargs)
        self._message = "File name in specified scope already exists"


class DatasetNotFound(RucioException):
    def __init__(self, *args, **kwargs):
        super(DatasetNotFound, self).__init__(args, kwargs)
        self._message = "Dataset not found in scope"


class DatasetObsolete(RucioException):
    def __init__(self, *args, **kwargs):
        super(DatasetObsolete, self).__init__(args, kwargs)
        self._message = "Dataset is obsolete"


class FileObsolete(RucioException):
    def __init__(self, *args, **kwargs):
        super(FileObsolete, self).__init__(args, kwargs)
        self._message = "File is obsolete"


class FileAssociationsRemain(RucioException):
    def __init__(self, *args, **kwargs):
        super(FileAssociationsRemain, self).__init__(args, kwargs)
        self._message = "Dataset has file associations"


class DatasetIsMonotonic(RucioException):
    def __init__(self, *args, **kwargs):
        super(DatasetIsMonotonic, self).__init__(args, kwargs)
        self._message = "Dataset is monotonic"


class FileNotFound(RucioException):
    def __init__(self, *args, **kwargs):
        super(FileNotFound, self).__init__(args, kwargs)
        self._message = "File not found in scope"


class DataIdentifierNotFound(RucioException):
    def __init__(self, *args, **kwargs):
        super(DataIdentifierNotFound, self).__init__(args, kwargs)
        self._message = "Data identifier not found"


class NameTypeError(RucioException):
    def __init__(self, *args, **kwargs):
        super(NameTypeError, self).__init__(args, kwargs)
        self._message = "Name is of the wrong type"


class ForbiddenSearch(RucioException):
    def __init__(self, *args, **kwargs):
        super(ForbiddenSearch, self).__init__(args, kwargs)
        self._message = "Wildcard search too broad"


class Duplicate(RucioException):
    def __init__(self, *args, **kwargs):
        super(Duplicate, self).__init__(args, kwargs)
        self._message = "An object with the same identifier already exists."


class NoAuthInformation(RucioException):
    def __init__(self, *args, **kwargs):
        super(NoAuthInformation, self).__init__(args)
        self._message = "No authentication information passed."


class MissingClientParameter(RucioException):
    def __init__(self, *args, **kwargs):
        super(MissingClientParameter, self).__init__(args)
        self._message = "Client parameters are missing."


class CannotAuthenticate(RucioException):
    def __init__(self, *args, **kwargs):
        super(CannotAuthenticate, self).__init__(args)
        self._message = "Cannot authenticate."


class ClientParameterMismatch(RucioException):
    def __init__(self, *args, **kwargs):
        super(ClientParameterMismatch, self).__init__(args)
        self._message = "Client parameters don\'t match."


class ClientProtocolNotSupported(RucioException):
    def __init__(self, *args, **kwargs):
        super(ClientProtocolNotSupported, self).__init__(args)
        self._message = "Client protocol not supported."


class IdentityError(RucioException):
    def __init__(self, *args, **kwargs):
        super(IdentityError, self).__init__()
        self._message = "Identity error."


class RSENotFound(RucioException):
    def __init__(self, *args, **kwargs):
        super(RSENotFound, self).__init__(args, kwargs)
        self._message = "RSE does not exist."


class RSETagNotFound(RucioException):
    def __init__(self, *args, **kwargs):
        super(RSETagNotFound, self).__init__(args, kwargs)
        self._message = "RSE Tag does not exist."


class InputValidationError(RucioException):
    def __init__(self, *args, **kwargs):
        super(InputValidationError, self).__init__(args, kwargs)
        self._message = "There is an error with one of the input parameters."


class SwitchProtocol(RucioException):
    def __init__(self, *args, **kwargs):
        super(SwitchProtocol, self).__init__(args, kwargs)
        self._message = "Protocol not supported."


class RSERepositoryNotFound(RucioException):
    def __init__(self, *args, **kwargs):
        super(RSERepositoryNotFound, self).__init__(args, kwargs)
        self._message = "Unable to locate RSE-Repository."


class ErrorLoadingCredentials(RucioException):
    def __init__(self, *args, **kwargs):
        super(ErrorLoadingCredentials, self).__init__(args, kwargs)
        self._message = "Unable to to load user credentials."


class ServiceUnavailable(RucioException):
    def __init__(self, *args, **kwargs):
        super(ServiceUnavailable, self).__init__(args, kwargs)
        self._message = "The requested service is not available at the moment."


class SourceNotFound(RucioException):
    def __init__(self, *args, **kwargs):
        super(SourceNotFound, self).__init__(args, kwargs)
        self._message = "Source file not found."


class DestinationNotAccessible(RucioException):
    def __init__(self, *args, **kwargs):
        super(DestinationNotAccessible, self).__init__(args, kwargs)
        self._message = "Access to local destination denied."


class RSENotConnected(RucioException):
    def __init__(self, *args, **kwargs):
        super(RSENotConnected, self).__init__(args, kwargs)
        self._message = "Connection to RSE not established."


class AccessDenied(RucioException):
    def __init__(self, *args, **kwargs):
        super(AccessDenied, self).__init__(args, kwargs)
        self._message = "Access to the requested resource denied."


class RSEAccessDenied(RucioException):
    def __init__(self, *args, **kwargs):
        super(RSEAccessDenied, self).__init__(args, kwargs)
        self._message = "Referrenced RSE not reachable."


class DatasetAccessDenied(RucioException):
    def __init__(self, *args, **kwargs):
        super(DatasetAccessDenied, self).__init__(args, kwargs)
        self._message = "Access to referrenced dataset denied."


class ScopeAccessDenied(RucioException):
    def __init__(self, *args, **kwargs):
        super(ScopeAccessDenied, self).__init__(args, kwargs)
        self._message = "Access to referrenced scope denied."


class RSEOverQuota(RucioException):
    def __init__(self, *args, **kwargs):
        super(RSEOverQuota, self).__init__(args, kwargs)
        self._message = "Quota of referrenced RSE is exceeded."


class InvalidMetadata(RucioException):
    def __init__(self, *args, **kwargs):
        super(InvalidMetadata, self).__init__(args, kwargs)
        self._message = "Provided metadata is considered invalid."


class FileReplicaAlreadyExists(RucioException):
    def __init__(self, *args, **kwargs):
        super(FileReplicaAlreadyExists, self).__init__(args, kwargs)
        self._message = "A replica of the file already exists."


class FileAlreadyExists(RucioException):
    def __init__(self, *args, **kwargs):
        super(FileAlreadyExists, self).__init__(args, kwargs)
        self._message = "The file already exists."


class FileConsistencyConflict(RucioException):
    def __init__(self, *args, **kwargs):
        super(FileConsistencyConflict, self).__init__(args, kwargs)
        self._message = "Error related to file consistency."


class InvalidReplicationRule(RucioException):
    def __init__(self, *args, **kwargs):
        super(InvalidReplicationRule, self).__init__(args, kwargs)
        self._message = "Provided replication rule is considered invalid."


class FullStorage(RucioException):
    def __init__(self, *args, **kwargs):
        super(FullStorage, self).__init__(args, kwargs)
        self._message = "The referrenced storage is out of disk space."


class SourceAccessDenied(RucioException):
    def __init__(self, *args, **kwargs):
        super(SourceAccessDenied, self).__init__(args, kwargs)
        self._message = "Access to local source file denied."


class DatabaseMigrationError(RucioException):
    def __init__(self, *args, **kwargs):
        super(DatabaseMigrationError, self).__init__(args, kwargs)
        self._message = "Error when migrating the database."
