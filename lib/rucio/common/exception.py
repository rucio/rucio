# Copyright European Organization for Nuclear Research (CERN) since 2012
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
    Exceptions used with Rucio.

    The base exception class is :class:`. RucioException`.
    Exceptions which are raised are all subclasses of it.

"""

from typing import Optional

from rucio.common.constraints import AUTHORIZED_VALUE_TYPES


class RucioException(Exception):
    """
    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.
    """

    def __init__(self, *args):
        super(RucioException, self).__init__(*args)
        self._message = "An unknown exception occurred."
        self.args = args
        self.error_code = 1
        self._error_string = None

    def __str__(self):
        self._error_string = self._message
        if len(self.args) > 0:
            # If there is a non-kwarg parameter, assume it's the error
            # message or reason description and tack it on to the end
            # of the exception message
            # Convert all arguments into their string representations...
            args = ["%s" % arg for arg in self.args if arg]
            self._error_string = (self._error_string + "\nDetails: %s" % '\n'.join(args))
        return self._error_string.strip()


# Please insert new exceptions sorted by error_code, not alphabetically.

class AccessDenied(RucioException):
    """
    AccessDenied
    """
    def __init__(self, *args):
        super(AccessDenied, self).__init__(*args)
        self._message = "Access to the requested resource denied."
        self.error_code = 2


class AccountNotFound(RucioException):
    """
    AccountNotFound
    """
    def __init__(self, *args):
        super(AccountNotFound, self).__init__(*args)
        self._message = "Account does not exist."
        self.error_code = 3


class CannotAuthenticate(RucioException):
    """
    CannotAuthenticate
    """
    def __init__(self, *args):
        super(CannotAuthenticate, self).__init__(*args)
        self._message = "Cannot authenticate."
        self.error_code = 4


class ClientParameterMismatch(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(ClientParameterMismatch, self).__init__(*args)
        self._message = "Client parameters don\'t match."
        self.error_code = 5


class ClientProtocolNotSupported(RucioException):
    """
    Client protocol not supported
    """

    def __init__(self, host: str, protocol: str, protocols_allowed: Optional[list[str]] = None, *args):
        super(ClientProtocolNotSupported, self).__init__(*args)
        self._message = f"Client protocol '{protocol}' not supported when connecting to host '{host}'.{' Allowed protocols: ' + ', '.join(protocols_allowed) if protocols_allowed else ''}"
        self.error_code = 6


class ConfigNotFound(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(ConfigNotFound, self).__init__(*args)
        self._message = "Configuration not found."
        self.error_code = 7


class ConfigurationError(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(ConfigurationError, self).__init__(*args)
        self._message = "Error during configuration."
        self.error_code = 8


class CounterNotFound(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(CounterNotFound, self).__init__(*args)
        self._message = "The requested counter does not exist."
        self.error_code = 9


class DatabaseException(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(DatabaseException, self).__init__(*args)
        self._message = "Database exception."
        self.error_code = 10


class DataIdentifierAlreadyExists(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(DataIdentifierAlreadyExists, self).__init__(*args)
        self._message = "Data Identifier Already Exists."
        self.error_code = 11


class DataIdentifierNotFound(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(DataIdentifierNotFound, self).__init__(*args)
        self._message = "Data identifier not found."
        self.error_code = 12


class DestinationNotAccessible(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(DestinationNotAccessible, self).__init__(*args)
        self._message = "Access to local destination denied."
        self.error_code = 13


class Duplicate(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(Duplicate, self).__init__(*args)
        self._message = "An object with the same identifier already exists."
        self.error_code = 14


class DuplicateContent(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(DuplicateContent, self).__init__(*args)
        self._message = "Data identifier already added to the destination content."
        self.error_code = 15


class DuplicateRule(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(DuplicateRule, self).__init__(*args)
        self._message = "A duplicate rule for this account, did, rse_expression, copies already exists."
        self.error_code = 16


class ErrorLoadingCredentials(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(ErrorLoadingCredentials, self).__init__(*args)
        self._message = "Unable to to load user credentials."
        self.error_code = 17


class FileAlreadyExists(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(FileAlreadyExists, self).__init__(*args)
        self._message = "The file already exists."
        self.error_code = 18


class FileConsistencyMismatch(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(FileConsistencyMismatch, self).__init__(*args)
        self._message = "Error related to file consistency."
        self.error_code = 19


class FileReplicaAlreadyExists(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(FileReplicaAlreadyExists, self).__init__(*args)
        self._message = "File name in specified scope already exists"
        self.error_code = 20


class ReplicaNotFound(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(ReplicaNotFound, self).__init__(*args)
        self._message = "Replica not found"
        self.error_code = 21


class ReplicaUnAvailable(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(ReplicaUnAvailable, self).__init__(*args)
        self._message = "Replica unavailable"
        self.error_code = 22


class FullStorage(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(FullStorage, self).__init__(*args)
        self._message = "The Referenced storage is out of disk space."
        self.error_code = 23


class IdentityError(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(IdentityError, self).__init__(*args)
        self._message = "Identity error."
        self.error_code = 24


class IdentityNotFound(RucioException):
    def __init__(self, *args):
        super(IdentityNotFound, self).__init__(*args)
        self._message = "This identity does not exist."
        self.error_code = 25


class InputValidationError(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(InputValidationError, self).__init__(*args)
        self._message = "There is an error with one of the input parameters."
        self.error_code = 26


class InsufficientAccountLimit(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(InsufficientAccountLimit, self).__init__(*args)
        self._message = "There is not enough quota left to fulfil the operation."
        self.error_code = 27


class InsufficientTargetRSEs(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(InsufficientTargetRSEs, self).__init__(*args)
        self._message = "There are not enough target RSEs to fulfil the request at this time."
        self.error_code = 28


class InvalidMetadata(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(InvalidMetadata, self).__init__(*args)
        self._message = "Provided metadata is considered invalid."
        self.error_code = 29


class InvalidObject(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(InvalidObject, self).__init__(*args)
        self._message = "Provided object does not match schema."
        self.error_code = 30


class InvalidReplicationRule(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(InvalidReplicationRule, self).__init__(*args)
        self._message = "Provided replication rule is considered invalid."
        self.error_code = 31


class InvalidRSEExpression(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(InvalidRSEExpression, self).__init__(*args)
        self._message = "Provided RSE expression is considered invalid."
        self.error_code = 32


class InvalidRuleWeight(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(InvalidRuleWeight, self).__init__(*args)
        self._message = "An invalid weight value/type is used for an RSE."
        self.error_code = 33


class InvalidType(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(InvalidType, self).__init__(*args)
        self._message = "Provided type is considered invalid."
        self.error_code = 34


class InvalidValueForKey(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(InvalidValueForKey, self).__init__(*args)
        self._message = "Invalid value for the key."
        self.error_code = 35


class InvalidRequest(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(InvalidRequest, self).__init__(*args)
        self._message = "Request is considered invalid."
        self.error_code = 36


class InvalidPath(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(InvalidPath, self).__init__(*args)
        self._message = "The path provided is invalid."
        self.error_code = 37


class KeyNotFound(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(KeyNotFound, self).__init__(*args)
        self._message = "Key does not exist."
        self.error_code = 38


class LifetimeExceptionDuplicate(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(LifetimeExceptionDuplicate, self).__init__(*args)
        self._message = "An exception already exists."
        self.error_code = 39


class LifetimeExceptionNotFound(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(LifetimeExceptionNotFound, self).__init__(*args)
        self._message = "Exception does not exist."
        self.error_code = 40


class ManualRuleApprovalBlocked(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(ManualRuleApprovalBlocked, self).__init__(*args)
        self._message = "Manual rule approval is blocked on this RSE."
        self.error_code = 41


class MissingClientParameter(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(MissingClientParameter, self).__init__(*args)
        self._message = "Client parameters are missing."
        self.error_code = 42


class MissingDependency(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(MissingDependency, self).__init__(*args)
        self._message = "One dependency is missing."
        self.error_code = 43


class MissingSourceReplica(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(MissingSourceReplica, self).__init__(*args)
        self._message = "Source replicas are missing to fulfil the request at this moment."
        self.error_code = 44


class NameTypeError(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(NameTypeError, self).__init__(*args)
        self._message = "Name is of the wrong type"
        self.error_code = 45


class NoAuthInformation(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(NoAuthInformation, self).__init__(*args)
        self._message = "No authentication information passed."
        self.error_code = 46


class NoFilesDownloaded(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(NoFilesDownloaded, self).__init__(*args)
        self._message = "None of the requested files have been downloaded."
        self.error_code = 75


class NotAllFilesDownloaded(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(NotAllFilesDownloaded, self).__init__(*args)
        self._message = "Not all of the requested files have been downloaded."
        self.error_code = 76


class ReplicationRuleCreationTemporaryFailed(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(ReplicationRuleCreationTemporaryFailed, self).__init__(*args)
        self._message = "The creation of the replication rule failed at this time. Please try again later."
        self.error_code = 47


class RequestNotFound(RucioException):
    def __init__(self, *args):
        super(RequestNotFound, self).__init__(*args)
        self._message = "A request for this DID and RSE does not exist."
        self.error_code = 48


class RSEAccessDenied(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(RSEAccessDenied, self).__init__(*args)
        self._message = "Referenced RSE not reachable."
        self.error_code = 49


class RSEWriteBlocked(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(RSEWriteBlocked, self).__init__(*args)
        self._message = "RSE excluded; not available for writing."
        self.error_code = 50


class RSENotConnected(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(RSENotConnected, self).__init__(*args)
        self._message = "Connection to RSE not established."
        self.error_code = 51


class RSENotFound(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(RSENotFound, self).__init__(*args)
        self._message = "RSE does not exist."
        self.error_code = 52


class RSEProtocolNotSupported(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(RSEProtocolNotSupported, self).__init__(*args)
        self._message = "RSE does not support requested protocol."
        self.error_code = 53


class RSEProtocolPriorityError(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(RSEProtocolPriorityError, self).__init__(*args)
        self._message = "RSE does not support provided protocol priority for protocol."
        self.error_code = 54


class RSEProtocolDomainNotSupported(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(RSEProtocolDomainNotSupported, self).__init__(*args)
        self._message = "RSE does not support requested protocol scope."
        self.error_code = 55


class RSEOperationNotSupported(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(RSEOperationNotSupported, self).__init__(*args)
        self._message = "RSE does not support requested operation."
        self.error_code = 56


class RSEFileNameNotSupported(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(RSEFileNameNotSupported, self).__init__(*args)
        self._message = "RSE does not support provided filename."
        self.error_code = 57


class RSEOverQuota(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(RSEOverQuota, self).__init__(*args)
        self._message = "Quota of Referenced RSE is exceeded."
        self.error_code = 58


class ResourceTemporaryUnavailable(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(ResourceTemporaryUnavailable, self).__init__(*args)
        self._message = "The resource is temporary not available."
        self.error_code = 59


class RuleNotFound(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(RuleNotFound, self).__init__(*args)
        self._message = "No replication rule found."
        self.error_code = 60


class RuleReplaceFailed(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(RuleReplaceFailed, self).__init__(*args)
        self._message = "The replace operation for the rule failed."
        self.error_code = 61


class ScratchDiskLifetimeConflict(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(ScratchDiskLifetimeConflict, self).__init__(*args)
        self._message = "The requested replication rule exceeds the maximum SCRATCHDISK lifetime of 15 days."
        self.error_code = 62


class ServiceUnavailable(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(ServiceUnavailable, self).__init__(*args)
        self._message = "The requested service is not available at the moment."
        self.error_code = 63


class ScopeAccessDenied(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(ScopeAccessDenied, self).__init__(*args)
        self._message = "Access to Referenced scope denied."
        self.error_code = 64


class ScopeNotFound(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(ScopeNotFound, self).__init__(*args)
        self._message = "Scope does not exist."
        self.error_code = 65


class SourceAccessDenied(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(SourceAccessDenied, self).__init__(*args)
        self._message = "Access to local source file denied."
        self.error_code = 66


class SourceNotFound(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(SourceNotFound, self).__init__(*args)
        self._message = "Source file not found."
        self.error_code = 67


class StagingAreaRuleRequiresLifetime(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(StagingAreaRuleRequiresLifetime, self).__init__(*args)
        self._message = "A rule involving a staging area requires a lifetime!"
        self.error_code = 68


class SubscriptionDuplicate(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(SubscriptionDuplicate, self).__init__(*args)
        self._message = "A subscription with the same identifier already exists."
        self.error_code = 69


class SubscriptionNotFound(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(SubscriptionNotFound, self).__init__(*args)
        self._message = "Subscription not found."
        self.error_code = 70


class UnsupportedDIDType(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(UnsupportedDIDType, self).__init__(*args)
        self._message = "Unsupported DID type for this operation. Only DATASET or FILE is allowed."
        self.error_code = 71


class UnsupportedOperation(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(UnsupportedOperation, self).__init__(*args)
        self._message = "The resource doesn't support the requested operation."
        self.error_code = 72


class UnsupportedStatus(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(UnsupportedStatus, self).__init__(*args)
        self._message = "Unsupported data identifier status."
        self.error_code = 73


class UnsupportedValueType(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(UnsupportedValueType, self).__init__(*args)
        self._message = "Unsupported type for the value. List of supported types: %s." % str(AUTHORIZED_VALUE_TYPES)
        self.error_code = 74


class MissingModuleException(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(MissingModuleException, self).__init__(*args)
        self._message = "The module is not installed."
        self.error_code = 77


class ServerConnectionException(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(ServerConnectionException, self).__init__(*args)
        self._message = "Cannot connect to the Rucio server."
        self.error_code = 78


class NoFilesUploaded(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(NoFilesUploaded, self).__init__(*args)
        self._message = "None of the given files have been uploaded."
        self.error_code = 79


class NotAllFilesUploaded(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(NotAllFilesUploaded, self).__init__(*args)
        self._message = "Not all of the given files have been uploaded."
        self.error_code = 80


class RSEChecksumUnavailable(RucioException):
    """
    Cannot retrieve checksum from RSE
    """
    def __init__(self, *args):
        super(RSEChecksumUnavailable, self).__init__(*args)
        self._message = "RSE checksum unavailable."
        self.error_code = 81


class UndefinedPolicy(RucioException):
    """
    Cannot find a defined policy in the Rucio config
    """
    def __init__(self, *args):
        super(UndefinedPolicy, self).__init__(*args)
        self._message = "No policy is defined."
        self.error_code = 82


class TransferToolTimeout(RucioException):
    """
    Timeout from the transfer tool
    """
    def __init__(self, *args):
        super(TransferToolTimeout, self).__init__(*args)
        self._message = "Timeout from the transfer tool."
        self.error_code = 83


class TransferToolWrongAnswer(RucioException):
    """
    Wrong answer returned by the transfer tool
    """
    def __init__(self, *args):
        super(TransferToolWrongAnswer, self).__init__(*args)
        self._message = "Wrong answer returned by the transfer tool."
        self.error_code = 84


class RSEAttributeNotFound(RucioException):
    """
    RSE attribute not found.
    """
    def __init__(self, *args):
        super(RSEAttributeNotFound, self).__init__(*args)
        self._message = "RSE attribute not found."
        self.error_code = 85


class UnsupportedKeyType(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(UnsupportedKeyType, self).__init__(*args)
        self._message = "Unsupported type for the key."
        self.error_code = 86


class MetalinkJsonParsingError(RucioException):
    """
    Failed to parse input with metalink and json
    """
    def __init__(self, data, metalink_err, json_err, *args):
        super(MetalinkJsonParsingError, self).__init__(*args)
        self._message = 'Failed parsing of %s. MetalinkError: %s. JsonError: %s' % (data, metalink_err, json_err)
        self.error_code = 87


class ReplicaIsLocked(RucioException):
    """
    Replica has one or more locks.
    """
    def __init__(self, *args):
        super(ReplicaIsLocked, self).__init__(*args)
        self._message = 'Replica is locked'
        self.error_code = 88


class UnsupportedRequestedContentType(RucioException):
    """
    The requested content type is not supported by the API endpoint.
    """
    def __init__(self, *args):
        super(UnsupportedRequestedContentType, self).__init__(*args)
        self._message = 'The requested content type is not supported.'
        self.error_code = 89


class DuplicateFileTransferSubmission(RucioException):
    """
    A transfer for the same file is already submitted to the Transfer Tool.
    """
    def __init__(self, *args):
        super(DuplicateFileTransferSubmission, self).__init__(*args)
        self._message = 'One or more files are already submitted to the transfer tool'
        self.error_code = 90


class DIDError(RucioException):
    """
    An operation related to DID type went wrong
    """
    def __init__(self, *args):
        super(DIDError, self).__init__(*args)
        self._message = 'Error using DID type'
        self.error_code = 91


class NoDistance(RucioException):
    """
    No distance can be found between 2 RSEs
    """
    def __init__(self, *args):
        super(NoDistance, self).__init__(*args)
        self._message = 'Cannot found a distance between 2 RSEs'
        self.error_code = 92


class PolicyPackageBaseException(RucioException):
    """
    Base exception for policy package errors.
    """
    def __init__(self, package: str, *args):
        super(PolicyPackageBaseException, self).__init__(*args)
        self.package = package


class PolicyPackageNotFound(PolicyPackageBaseException):
    """
    The policy package specified in the config file was not found
    """
    def __init__(self, package: str, *args):
        super(PolicyPackageNotFound, self).__init__(package, *args)
        self._message = 'The specified policy package %s was not found' % self.package
        self.error_code = 93


class CannotAuthorize(RucioException):
    """
    Failed to authorize an operation.
    """
    def __init__(self, *args):
        super(CannotAuthorize, self).__init__(*args)
        self._message = 'Can not authorize operation.'
        self.error_code = 94


class SubscriptionWrongParameter(RucioException):
    """
    RucioException
    """
    def __init__(self, *args):
        super(SubscriptionWrongParameter, self).__init__(*args)
        self._message = "Subscription wrong parameters"
        self.error_code = 95


class VONotFound(RucioException):
    """
    Requested VO does not exist.
    """
    def __init__(self, *args):
        super(VONotFound, self).__init__(*args)
        self._message = 'The requested VO does not exist'
        self.error_code = 96


class UnsupportedAccountName(RucioException):
    """
    Requested account name is not supported for users.
    """
    def __init__(self, *args):
        super(UnsupportedAccountName, self).__init__(*args)
        self._message = 'The requested account name cannot be used'
        self.error_code = 97


class DuplicateCriteriaInDIDFilter(RucioException):
    """
    Duplicate criteria found in DID filter.
    """
    def __init__(self, *args):
        super(DuplicateCriteriaInDIDFilter, self).__init__(*args)
        self._message = 'Duplicate criteria for key/operator in filter expression: {}'.format(args[0])
        self.error_code = 98


class DIDFilterSyntaxError(RucioException):
    """
    DID filter is not parsable.
    """
    def __init__(self, *args):
        super(DIDFilterSyntaxError, self).__init__(*args)
        self._message = 'Syntax error in filter expression.'
        self.error_code = 99


class InvalidAlgorithmName(RucioException):
    """
    The given algorithm name is not valid for the VO.
    """
    def __init__(self, algorithm, vo, *args):
        super(InvalidAlgorithmName, self).__init__(*args)
        self.message = 'Algorithm name %s is not valid for VO %s' % (algorithm, vo)
        self.error_code = 100


class FilterEngineGenericError(RucioException):
    """
    Generic Filter Engine error.
    """
    def __init__(self, *args):
        super(FilterEngineGenericError, self).__init__(*args)
        self._message = 'Generic filter engine error.'
        self.error_code = 101


class MetadataSchemaMismatchError(RucioException):
    """
    External table does not match expected table schema.
    """
    def __init__(self, *args):
        super(MetadataSchemaMismatchError, self).__init__(*args)
        self._message = 'The external table does not match the expected table schema.'
        self.error_code = 102


class PolicyPackageVersionError(PolicyPackageBaseException):
    """
    Policy package is not compatible with this version of Rucio.
    """
    def __init__(self, package: str, rucio_version: str, supported_versionset: str, *args):
        super(PolicyPackageVersionError, self).__init__(package, *args)
        self.rucio_version = rucio_version
        self.supported_versionset = supported_versionset
        self._message = 'Policy package %s is not compatible with this Rucio version.\nRucio version: %s\nVersions supported by the package: %s' % (
            self.package,
            self.rucio_version,
            self.supported_versionset
        )
        self.error_code = 103


class InvalidSourceReplicaExpression(RucioException):
    """
    Source Replica Expression Considered Invalid
    """

    def __init__(self, *args):
        super(InvalidSourceReplicaExpression, self).__init__(*args)
        self._message = 'Provided Source Replica expression is considered invalid.'
        self.error_code = 104


class DeprecationError(RucioException):
    """
    Function has been deprecated.
    """
    def __init__(self, *args):
        super(DeprecationError, self).__init__(*args)
        self._message = 'Command or function has been deprecated.'
        self.error_code = 105


class SortingAlgorithmNotSupported(RucioException):
    """
    Sorting algorithm is not supported.
    """
    def __init__(self, *args):
        super(SortingAlgorithmNotSupported, self).__init__(*args)
        self._message = 'Sorting algorithm is not supported.'
        self.error_code = 106


class ErrorLoadingPolicyPackage(PolicyPackageBaseException):
    """
    An error occurred while loading the policy package.
    """
    def __init__(self, package: str, *args):
        super(ErrorLoadingPolicyPackage, self).__init__(package, *args)
        self._message = 'An error occurred while loading the policy package %s' % self.package
        self.error_code = 107


class TraceValidationSchemaNotFound(RucioException):
    """
    Trace validation schema not found.
    """
    def __init__(self, *args):
        super(TraceValidationSchemaNotFound, self).__init__(*args)
        self._message = 'Trace validation schema not found.'
        self.error_code = 108


class PolicyPackageIsNotVersioned(PolicyPackageBaseException):
    """
    Policy package does not contain version information.
    """
    def __init__(self, package: str, *args):
        super(PolicyPackageIsNotVersioned, self).__init__(package, *args)
        self._message = 'Policy package %s does not include information about which Rucio versions it supports.' % self.package
        self.error_code = 109


class UnsupportedMetadataPlugin(RucioException):
    """
    Raised when attempting to use a metadata plugin that is not enabled on the server.
    """
    def __init__(self, *args):
        super(UnsupportedMetadataPlugin, self).__init__(*args)
        self._message = "The requested metadata plugin is not enabled on the server."
        self.error_code = 110


class ChecksumCalculationError(RucioException):
    """
    An error occurred while calculating the checksum.
    """
    def __init__(
            self,
            algorithm_name: str,
            filepath: str,
            *args,
            **kwargs
    ):
        super(ChecksumCalculationError, self).__init__(*args, **kwargs)
        self.algorithm_name = algorithm_name
        self.filepath = filepath
        self._message = 'An error occurred while calculating the %s checksum of file %s.' % (self.algorithm_name, self.filepath)
        self.error_code = 111


class ConfigLoadingError(RucioException):
    """
    An error occurred while loading the configuration.
    """
    def __init__(
            self,
            config_file: str,
            *args,
            **kwargs
    ):
        super(ConfigLoadingError, self).__init__(*args, **kwargs)
        self._message = 'Could not load Rucio configuration file. Rucio tried loading the following configuration file:\n\t %s' % (config_file)
        self.error_code = 112


class ClientProtocolNotFound(RucioException):
    """
    Missing protocol in client configuration (e.g. no http/https in url).
    """

    def __init__(self, host: str, protocols_allowed: Optional[list[str]] = None, *args):
        super(ClientProtocolNotFound, self).__init__(*args)
        self._message = f"Client protocol missing when connecting to host '{host}'.{' Allowed protocols: ' + ', '.join(protocols_allowed) if protocols_allowed else ''}"
        self.error_code = 113


class ConnectionParameterNotFound(RucioException):
    """
    Thrown when a required connection parameter is missing.
    """
    def __init__(self, param: str, *args):
        super(ConnectionParameterNotFound, self).__init__(*args)
        self._message = f"Required connection parameter '{param}' is not provided."
        self.error_code = 114


class OpenDataError(RucioException):
    """
    Error related to open data.
    """

    def __init__(self, *args):
        super(OpenDataError, self).__init__(*args)
        self._message = "Error related to open data."
        self.error_code = 115


class OpenDataDataIdentifierNotFound(OpenDataError):
    """
    Throws when the data identifier is not in the open data catalog.
    """

    def __init__(self, *args):
        super(OpenDataDataIdentifierNotFound, self).__init__(*args)
        self._message = "Data identifier not found in the open data catalog."
        self.error_code = 116


class OpenDataDataIdentifierAlreadyExists(OpenDataError):
    """
    Throws when the data identifier already exists in the open data catalog.
    """

    def __init__(self, *args):
        super(OpenDataDataIdentifierAlreadyExists, self).__init__(*args)
        self._message = "Data identifier already exists in the open data catalog."
        self.error_code = 117


class OpenDataInvalidState(OpenDataError):
    """
    Throws when the open data entry is in an invalid state.
    """

    def __init__(self, *args):
        super(OpenDataInvalidState, self).__init__(*args)
        self._message = "Open data entry is in an invalid state."
        self.error_code = 118


class OpenDataInvalidStateUpdate(OpenDataError):
    """
    Throws when a forbidden state update is attempted (e.g. from public to draft).
    """

    def __init__(self, *args):
        super(OpenDataInvalidStateUpdate, self).__init__(*args)
        self._message = "Invalid state update attempted on open data entry."
        self.error_code = 119
