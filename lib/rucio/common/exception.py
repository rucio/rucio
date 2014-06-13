# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch> , 2012
# - Angelos Molfetas, <angelos.molfetas@cern,ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012, 2014
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2011-2013
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2012-2013
# - Martin Barisits, <martin.barisits@cern.ch>, 2012-2014
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2014


"""Exceptions used with Rucio.

The base exception class is :class:`. RucioException`.
Exceptions which are raised are all subclasses of it.

"""

from rucio.common.constraints import AUTHORIZED_VALUE_TYPES


class RucioException(Exception):
    """
    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.
    """

    def __init__(self, *args, **kwargs):
        self._message = "An unknown exception occurred."
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
        return self._error_string.strip()


# Please insert new exceptions in alphabetic order

class AccessDenied(RucioException):
    def __init__(self, *args, **kwargs):
        super(AccessDenied, self).__init__(args, kwargs)
        self._message = "Access to the requested resource denied."


class AccountNotFound(RucioException):
    def __init__(self, *args, **kwargs):
        super(AccountNotFound, self).__init__(args, kwargs)
        self._message = "Account does not exist."


class CannotAuthenticate(RucioException):
    def __init__(self, *args, **kwargs):
        super(CannotAuthenticate, self).__init__(args, kwargs)
        self._message = "Cannot authenticate."


class ClientParameterMismatch(RucioException):
    def __init__(self, *args, **kwargs):
        super(ClientParameterMismatch, self).__init__(args, kwargs)
        self._message = "Client parameters don\'t match."


class ClientProtocolNotSupported(RucioException):
    def __init__(self, *args, **kwargs):
        super(ClientProtocolNotSupported, self).__init__(args, kwargs)
        self._message = "Client protocol not supported."


class ConfigNotFound(RucioException):
    def __init__(self, *args, **kwargs):
        super(ConfigNotFound, self).__init__(args, kwargs)
        self._message = "Configuration not found."


class ConfigurationError(RucioException):
    def __init__(self, *args, **kwargs):
        super(ConfigurationError, self).__init__(args, kwargs)
        self._message = "Error during configuration."


class CounterNotFound(RucioException):
    def __init__(self, *args, **kwargs):
        super(CounterNotFound, self).__init__(args, kwargs)
        self._message = "The requested counter does not exist."


class DatabaseException(RucioException):
    def __init__(self, *args, **kwargs):
        super(DatabaseException, self).__init__(args, kwargs)
        self._message = "Database exception."


class DatasetAccessDenied(RucioException):
    def __init__(self, *args, **kwargs):
        super(DatasetAccessDenied, self).__init__(args, kwargs)
        self._message = "Access to referrenced dataset denied."


class DatasetAlreadyExists(RucioException):
    def __init__(self, *args, **kwargs):
        super(DatasetAlreadyExists, self).__init__(args, kwargs)
        self._message = "Dataset name in specified scope already exists"


class DatabaseMigrationError(RucioException):
    def __init__(self, *args, **kwargs):
        super(DatabaseMigrationError, self).__init__(args, kwargs)
        self._message = "Error when migrating the database."


class DataIdentifierAlreadyExists(RucioException):
    def __init__(self, *args, **kwargs):
        super(DataIdentifierAlreadyExists, self).__init__(args, kwargs)
        self._message = "Data Identifier Already Exists."


class DataIdentifierNotFound(RucioException):
    def __init__(self, *args, **kwargs):
        super(DataIdentifierNotFound, self).__init__(args, kwargs)
        self._message = "Data identifier not found."


class DatasetIsMonotonic(RucioException):
    def __init__(self, *args, **kwargs):
        super(DatasetIsMonotonic, self).__init__(args, kwargs)
        self._message = "Dataset is monotonic"


class DatasetNotFound(RucioException):
    def __init__(self, *args, **kwargs):
        super(DatasetNotFound, self).__init__(args, kwargs)
        self._message = "Dataset not found in scope"


class DatasetObsolete(RucioException):
    def __init__(self, *args, **kwargs):
        super(DatasetObsolete, self).__init__(args, kwargs)
        self._message = "Dataset is obsolete"


class DestinationNotAccessible(RucioException):
    def __init__(self, *args, **kwargs):
        super(DestinationNotAccessible, self).__init__(args, kwargs)
        self._message = "Access to local destination denied."


class Duplicate(RucioException):
    def __init__(self, *args, **kwargs):
        super(Duplicate, self).__init__(args, kwargs)
        self._message = "An object with the same identifier already exists."


class DuplicateContent(RucioException):
    def __init__(self, *args, **kwargs):
        super(DuplicateContent, self).__init__(args, kwargs)
        self._message = "Data identifier already added to the destination content."


class ErrorLoadingCredentials(RucioException):
    def __init__(self, *args, **kwargs):
        super(ErrorLoadingCredentials, self).__init__(args, kwargs)
        self._message = "Unable to to load user credentials."


class FileAlreadyExists(RucioException):
    def __init__(self, *args, **kwargs):
        super(FileAlreadyExists, self).__init__(args, kwargs)
        self._message = "The file already exists."


class FileAssociationsRemain(RucioException):
    def __init__(self, *args, **kwargs):
        super(FileAssociationsRemain, self).__init__(args, kwargs)
        self._message = "Dataset has file associations"


class FileConsistencyMismatch(RucioException):
    def __init__(self, *args, **kwargs):
        super(FileConsistencyMismatch, self).__init__(args, kwargs)
        self._message = "Error related to file consistency."


class FileNotFound(RucioException):
    def __init__(self, *args, **kwargs):
        super(FileNotFound, self).__init__(args, kwargs)
        self._message = "File not found in scope"


class FileObsolete(RucioException):
    def __init__(self, *args, **kwargs):
        super(FileObsolete, self).__init__(args, kwargs)
        self._message = "File is obsolete"


class FileReplicaAlreadyExists(RucioException):
    def __init__(self, *args, **kwargs):
        super(FileReplicaAlreadyExists, self).__init__(args, kwargs)
        self._message = "File name in specified scope already exists"


class ReplicaNotFound(RucioException):
    def __init__(self, *args, **kwargs):
        super(ReplicaNotFound, self).__init__(args, kwargs)
        self._message = "Replica not found"


class ForbiddenSearch(RucioException):
    def __init__(self, *args, **kwargs):
        super(ForbiddenSearch, self).__init__(args, kwargs)
        self._message = "Wildcard search too broad"


class FullStorage(RucioException):
    def __init__(self, *args, **kwargs):
        super(FullStorage, self).__init__(args, kwargs)
        self._message = "The referrenced storage is out of disk space."


class IdentityError(RucioException):
    def __init__(self, *args, **kwargs):
        super(IdentityError, self).__init__(args, kwargs)
        self._message = "Identity error."


class InputValidationError(RucioException):
    def __init__(self, *args, **kwargs):
        super(InputValidationError, self).__init__(args, kwargs)
        self._message = "There is an error with one of the input parameters."


class InsufficientAccountLimit(RucioException):
    def __init__(self, *args, **kwargs):
        super(InsufficientAccountLimit, self).__init__(args, kwargs)
        self._message = "There is not enough space left to fulfil the operation."


class InsufficientTargetRSEs(RucioException):
    def __init__(self, *args, **kwargs):
        super(InsufficientTargetRSEs, self).__init__(args, kwargs)
        self._message = "There are not enough target RSEs to fulfil the request at this time."


class InvalidMetadata(RucioException):
    def __init__(self, *args, **kwargs):
        super(InvalidMetadata, self).__init__(args, kwargs)
        self._message = "Provided metadata is considered invalid."


class InvalidObject(RucioException):
    def __init__(self, *args, **kwargs):
        super(InvalidObject, self).__init__(args, kwargs)
        self._message = "Provided object does not match schema."


class InvalidReplicaLock(RucioException):
    def __init__(self, *args, **kwargs):
        super(InvalidReplicaLock, self).__init__(args, kwargs)
        self._message = "Provided replica lock is considered invalid."


class InvalidReplicationRule(RucioException):
    def __init__(self, *args, **kwargs):
        super(InvalidReplicationRule, self).__init__(args, kwargs)
        self._message = "Provided replication rule is considered invalid."


class InvalidRSEExpression(RucioException):
    def __init__(self, *args, **kwargs):
        super(InvalidRSEExpression, self).__init__(args, kwargs)
        self._message = "Provided RSE expression is considered invalid."


class InvalidRuleWeight(RucioException):
    def __init__(self, *args, **kwargs):
        super(InvalidRuleWeight, self).__init__(args, kwargs)
        self._message = "An invalid weight value/type is used for an RSE."


class InvalidType(RucioException):
    def __init__(self, *args, **kwargs):
        super(InvalidType, self).__init__(args, kwargs)
        self._message = "Provided type is considered invalid."


class InvalidValueForKey(RucioException):
    def __init__(self, *args, **kwargs):
        super(InvalidValueForKey, self).__init__(args, kwargs)
        self._message = "Invalid value for the key."


class KeyNotFound(RucioException):
    def __init__(self, *args, **kwargs):
        super(KeyNotFound, self).__init__(args, kwargs)
        self._message = "Key does not exist."


class MissingClientParameter(RucioException):
    def __init__(self, *args, **kwargs):
        super(MissingClientParameter, self).__init__(args, kwargs)
        self._message = "Client parameters are missing."


class MissingFileParameter(RucioException):
    def __init__(self, *args, **kwargs):
        super(MissingFileParameter, self).__init__(args, kwargs)
        self._message = "File parameter is missing."


class NameTypeError(RucioException):
    def __init__(self, *args, **kwargs):
        super(NameTypeError, self).__init__(args, kwargs)
        self._message = "Name is of the wrong type"


class NoAuthInformation(RucioException):
    def __init__(self, *args, **kwargs):
        super(NoAuthInformation, self).__init__(args, kwargs)
        self._message = "No authentication information passed."


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


class ReplicationRuleCreationFailed(RucioException):
    def __init__(self, *args, **kwargs):
        super(ReplicationRuleCreationFailed, self).__init__(args, kwargs)
        self._message = "The creation of the replication rule failed at this time. Please try again later."


class RSEAccessDenied(RucioException):
    def __init__(self, *args, **kwargs):
        super(RSEAccessDenied, self).__init__(args, kwargs)
        self._message = "Referrenced RSE not reachable."


class RSENotConnected(RucioException):
    def __init__(self, *args, **kwargs):
        super(RSENotConnected, self).__init__(args, kwargs)
        self._message = "Connection to RSE not established."


class RSENotFound(RucioException):
    def __init__(self, *args, **kwargs):
        super(RSENotFound, self).__init__(args, kwargs)
        self._message = "RSE does not exist."


class RSEProtocolNotSupported(RucioException):
    def __init__(self, *args, **kwargs):
        super(RSEProtocolNotSupported, self).__init__(args, kwargs)
        self._message = "RSE does not support requested protocol."


class RSEProtocolPriorityError(RucioException):
    def __init__(self, *args, **kwargs):
        super(RSEProtocolPriorityError, self).__init__(args, kwargs)
        self._message = "RSE does not support provided protocol priority for protocol."


class RSEProtocolDomainNotSupported(RucioException):
    def __init__(self, *args, **kwargs):
        super(RSEProtocolDomainNotSupported, self).__init__(args, kwargs)
        self._message = "RSE does not support requested protocol scope."


class RSEOperationNotSupported(RucioException):
    def __init__(self, *args, **kwargs):
        super(RSEOperationNotSupported, self).__init__(args, kwargs)
        self._message = "RSE does not support requested operation."


class RSEFileNameNotSupported(RucioException):
    def __init__(self, *args, **kwargs):
        super(RSEFileNameNotSupported, self).__init__(args, kwargs)
        self._message = "RSE does not support provided filename."


class RSEOverQuota(RucioException):
    def __init__(self, *args, **kwargs):
        super(RSEOverQuota, self).__init__(args, kwargs)
        self._message = "Quota of referrenced RSE is exceeded."


class RSETagNotFound(RucioException):
    def __init__(self, *args, **kwargs):
        super(RSETagNotFound, self).__init__(args, kwargs)
        self._message = "RSE Tag does not exist."


class RessourceTemporaryUnavailable(RucioException):
    def __init__(self, *args, **kwargs):
        super(RessourceTemporaryUnavailable, self).__init__(args, kwargs)
        self._message = "The ressource is temporary not available."


class RuleNotFound(RucioException):
    def __init__(self, *args, **kwargs):
        super(RuleNotFound, self).__init__(args, kwargs)
        self._message = "No replication rule found."


class ServiceUnavailable(RucioException):
    def __init__(self, *args, **kwargs):
        super(ServiceUnavailable, self).__init__(args, kwargs)
        self._message = "The requested service is not available at the moment."


class ScopeAccessDenied(RucioException):
    def __init__(self, *args, **kwargs):
        super(ScopeAccessDenied, self).__init__(args, kwargs)
        self._message = "Access to referrenced scope denied."


class ScopeNotFound(RucioException):
    def __init__(self, *args, **kwargs):
        super(ScopeNotFound, self).__init__(args, kwargs)
        self._message = "Scope does not exist."


class SourceAccessDenied(RucioException):
    def __init__(self, *args, **kwargs):
        super(SourceAccessDenied, self).__init__(args, kwargs)
        self._message = "Access to local source file denied."


class SourceNotFound(RucioException):
    def __init__(self, *args, **kwargs):
        super(SourceNotFound, self).__init__(args, kwargs)
        self._message = "Source file not found."


class SubscriptionDuplicate(RucioException):
    def __init__(self, *args, **kwargs):
        super(SubscriptionDuplicate, self).__init__(args, kwargs)
        self._message = "A subscription with the same identifier already exists."


class SubscriptionNotFound(RucioException):
    def __init__(self, *args, **kwargs):
        super(SubscriptionNotFound, self).__init__(args, kwargs)
        self._message = "Subscription not found."


class UnsupportedOperation(RucioException):
    def __init__(self, *args, **kwargs):
        super(UnsupportedOperation, self).__init__(args, kwargs)
        self._message = "The resource doesn't support the requested operation."


class UnsupportedStatus(RucioException):
    def __init__(self, *args, **kwargs):
        super(UnsupportedStatus, self).__init__(args, kwargs)
        self._message = "Unsupported data identifier status."


class UnsupportedValueType(RucioException):
    def __init__(self, *args, **kwargs):
        super(UnsupportedValueType, self).__init__(args, kwargs)
        self._message = "Unsupported type for the value. List of supported types: %s." % str(AUTHORIZED_VALUE_TYPES)
