# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch> , 2012
# - Angelos Molfetas, <angelos.molfetas@cern,ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012, 2014-2015
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2011-2013
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2012-2013
# - Martin Barisits, <martin.barisits@cern.ch>, 2012-2016
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2017
# - Wen Guan, <wen.guan@cern.ch>, 2014


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
        super(RucioException, self).__init__(args, kwargs)
        self._message = "An unknown exception occurred."
        self.args = args
        self.kwargs = kwargs
        self._error_string = None

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
    """
    AccessDenied
    """
    def __init__(self, *args, **kwargs):
        super(AccessDenied, self).__init__(args, kwargs)
        self._message = "Access to the requested resource denied."


class AccountNotFound(RucioException):
    """
    AccountNotFound
    """
    def __init__(self, *args, **kwargs):
        super(AccountNotFound, self).__init__(args, kwargs)
        self._message = "Account does not exist."


class CannotAuthenticate(RucioException):
    """
    CannotAuthenticate
    """
    def __init__(self, *args, **kwargs):
        super(CannotAuthenticate, self).__init__(args, kwargs)
        self._message = "Cannot authenticate."


class ClientParameterMismatch(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(ClientParameterMismatch, self).__init__(args, kwargs)
        self._message = "Client parameters don\'t match."


class ClientProtocolNotSupported(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(ClientProtocolNotSupported, self).__init__(args, kwargs)
        self._message = "Client protocol not supported."


class ConfigNotFound(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(ConfigNotFound, self).__init__(args, kwargs)
        self._message = "Configuration not found."


class ConfigurationError(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(ConfigurationError, self).__init__(args, kwargs)
        self._message = "Error during configuration."


class CounterNotFound(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(CounterNotFound, self).__init__(args, kwargs)
        self._message = "The requested counter does not exist."


class DatabaseException(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(DatabaseException, self).__init__(args, kwargs)
        self._message = "Database exception."


class DataIdentifierAlreadyExists(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(DataIdentifierAlreadyExists, self).__init__(args, kwargs)
        self._message = "Data Identifier Already Exists."


class DataIdentifierNotFound(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(DataIdentifierNotFound, self).__init__(args, kwargs)
        self._message = "Data identifier not found."


class DestinationNotAccessible(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(DestinationNotAccessible, self).__init__(args, kwargs)
        self._message = "Access to local destination denied."


class Duplicate(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(Duplicate, self).__init__(args, kwargs)
        self._message = "An object with the same identifier already exists."


class DuplicateContent(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(DuplicateContent, self).__init__(args, kwargs)
        self._message = "Data identifier already added to the destination content."


class DuplicateRule(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(DuplicateRule, self).__init__(args, kwargs)
        self._message = "A duplicate rule for this account, did, rse_expression, copies already exists."


class ErrorLoadingCredentials(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(ErrorLoadingCredentials, self).__init__(args, kwargs)
        self._message = "Unable to to load user credentials."


class FileAlreadyExists(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(FileAlreadyExists, self).__init__(args, kwargs)
        self._message = "The file already exists."


class FileConsistencyMismatch(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(FileConsistencyMismatch, self).__init__(args, kwargs)
        self._message = "Error related to file consistency."


class FileReplicaAlreadyExists(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(FileReplicaAlreadyExists, self).__init__(args, kwargs)
        self._message = "File name in specified scope already exists"


class ReplicaNotFound(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(ReplicaNotFound, self).__init__(args, kwargs)
        self._message = "Replica not found"


class ReplicaUnAvailable(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(ReplicaUnAvailable, self).__init__(args, kwargs)
        self._message = "Replica unavailable"


class FullStorage(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(FullStorage, self).__init__(args, kwargs)
        self._message = "The Referenced storage is out of disk space."


class IdentityError(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(IdentityError, self).__init__(args, kwargs)
        self._message = "Identity error."


class IdentityNotFound(RucioException):
    def __init__(self, *args, **kwargs):
        super(IdentityNotFound, self).__init__(args, kwargs)
        self._message = "This identity does not exist."


class InputValidationError(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(InputValidationError, self).__init__(args, kwargs)
        self._message = "There is an error with one of the input parameters."


class InsufficientAccountLimit(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(InsufficientAccountLimit, self).__init__(args, kwargs)
        self._message = "There is not enough quota left to fulfil the operation."


class InsufficientTargetRSEs(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(InsufficientTargetRSEs, self).__init__(args, kwargs)
        self._message = "There are not enough target RSEs to fulfil the request at this time."


class InvalidMetadata(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(InvalidMetadata, self).__init__(args, kwargs)
        self._message = "Provided metadata is considered invalid."


class InvalidObject(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(InvalidObject, self).__init__(args, kwargs)
        self._message = "Provided object does not match schema."


class InvalidReplicationRule(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(InvalidReplicationRule, self).__init__(args, kwargs)
        self._message = "Provided replication rule is considered invalid."


class InvalidRSEExpression(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(InvalidRSEExpression, self).__init__(args, kwargs)
        self._message = "Provided RSE expression is considered invalid."


class InvalidRuleWeight(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(InvalidRuleWeight, self).__init__(args, kwargs)
        self._message = "An invalid weight value/type is used for an RSE."


class InvalidType(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(InvalidType, self).__init__(args, kwargs)
        self._message = "Provided type is considered invalid."


class InvalidValueForKey(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(InvalidValueForKey, self).__init__(args, kwargs)
        self._message = "Invalid value for the key."


class InvalidRequest(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(InvalidRequest, self).__init__(args, kwargs)
        self._message = "Request is considered invalid."


class InvalidPath(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(InvalidPath, self).__init__(args, kwargs)
        self._message = "The path provided is invalid."


class KeyNotFound(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(KeyNotFound, self).__init__(args, kwargs)
        self._message = "Key does not exist."


class LifetimeExceptionDuplicate(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(LifetimeExceptionDuplicate, self).__init__(args, kwargs)
        self._message = "An exception already exists."


class LifetimeExceptionNotFound(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(LifetimeExceptionNotFound, self).__init__(args, kwargs)
        self._message = "Exception does not exist."


class ManualRuleApprovalBlocked(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(ManualRuleApprovalBlocked, self).__init__(args, kwargs)
        self._message = "Manual rule approval is blocked on this RSE."


class MissingClientParameter(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(MissingClientParameter, self).__init__(args, kwargs)
        self._message = "Client parameters are missing."


class MissingDependency(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(MissingDependency, self).__init__(args, kwargs)
        self._message = "One dependency is missing."


class MissingSourceReplica(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(MissingSourceReplica, self).__init__(args, kwargs)
        self._message = "Source replicas are missing to fulfil the request at this moment."


class NameTypeError(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(NameTypeError, self).__init__(args, kwargs)
        self._message = "Name is of the wrong type"


class NoAuthInformation(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(NoAuthInformation, self).__init__(args, kwargs)
        self._message = "No authentication information passed."


class ReplicationRuleCreationTemporaryFailed(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(ReplicationRuleCreationTemporaryFailed, self).__init__(args, kwargs)
        self._message = "The creation of the replication rule failed at this time. Please try again later."


class RequestNotFound(RucioException):
    def __init__(self, *args, **kwargs):
        super(RequestNotFound, self).__init__(args, kwargs)
        self._message = "A request for this DID and RSE does not exist."


class RSEAccessDenied(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(RSEAccessDenied, self).__init__(args, kwargs)
        self._message = "Referenced RSE not reachable."


class RSEBlacklisted(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(RSEBlacklisted, self).__init__(args, kwargs)
        self._message = "RSE excluded due to write blacklisting."


class RSENotConnected(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(RSENotConnected, self).__init__(args, kwargs)
        self._message = "Connection to RSE not established."


class RSENotFound(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(RSENotFound, self).__init__(args, kwargs)
        self._message = "RSE does not exist."


class RSEProtocolNotSupported(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(RSEProtocolNotSupported, self).__init__(args, kwargs)
        self._message = "RSE does not support requested protocol."


class RSEProtocolPriorityError(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(RSEProtocolPriorityError, self).__init__(args, kwargs)
        self._message = "RSE does not support provided protocol priority for protocol."


class RSEProtocolDomainNotSupported(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(RSEProtocolDomainNotSupported, self).__init__(args, kwargs)
        self._message = "RSE does not support requested protocol scope."


class RSEOperationNotSupported(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(RSEOperationNotSupported, self).__init__(args, kwargs)
        self._message = "RSE does not support requested operation."


class RSEFileNameNotSupported(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(RSEFileNameNotSupported, self).__init__(args, kwargs)
        self._message = "RSE does not support provided filename."


class RSEOverQuota(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(RSEOverQuota, self).__init__(args, kwargs)
        self._message = "Quota of Referenced RSE is exceeded."


class ResourceTemporaryUnavailable(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(ResourceTemporaryUnavailable, self).__init__(args, kwargs)
        self._message = "The resource is temporary not available."


class RuleNotFound(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(RuleNotFound, self).__init__(args, kwargs)
        self._message = "No replication rule found."


class RuleReplaceFailed(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(RuleReplaceFailed, self).__init__(args, kwargs)
        self._message = "The replace operation for the rule failed."


class ScratchDiskLifetimeConflict(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(ScratchDiskLifetimeConflict, self).__init__(args, kwargs)
        self._message = "The requested replication rule exceeds the maximum SCRATCHDISK lifetime of 15 days."


class ServiceUnavailable(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(ServiceUnavailable, self).__init__(args, kwargs)
        self._message = "The requested service is not available at the moment."


class ScopeAccessDenied(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(ScopeAccessDenied, self).__init__(args, kwargs)
        self._message = "Access to Referenced scope denied."


class ScopeNotFound(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(ScopeNotFound, self).__init__(args, kwargs)
        self._message = "Scope does not exist."


class SourceAccessDenied(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(SourceAccessDenied, self).__init__(args, kwargs)
        self._message = "Access to local source file denied."


class SourceNotFound(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(SourceNotFound, self).__init__(args, kwargs)
        self._message = "Source file not found."


class StagingAreaRuleRequiresLifetime(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(StagingAreaRuleRequiresLifetime, self).__init__(args, kwargs)
        self._message = "A rule involving a staging area requires a lifetime!"


class SubscriptionDuplicate(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(SubscriptionDuplicate, self).__init__(args, kwargs)
        self._message = "A subscription with the same identifier already exists."


class SubscriptionNotFound(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(SubscriptionNotFound, self).__init__(args, kwargs)
        self._message = "Subscription not found."


class UnsupportedOperation(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(UnsupportedOperation, self).__init__(args, kwargs)
        self._message = "The resource doesn't support the requested operation."


class UnsupportedStatus(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(UnsupportedStatus, self).__init__(args, kwargs)
        self._message = "Unsupported data identifier status."


class UnsupportedValueType(RucioException):
    """
    RucioException
    """
    def __init__(self, *args, **kwargs):
        super(UnsupportedValueType, self).__init__(args, kwargs)
        self._message = "Unsupported type for the value. List of supported types: %s." % str(AUTHORIZED_VALUE_TYPES)
