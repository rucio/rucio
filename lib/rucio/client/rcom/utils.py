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
import errno
import os
import sys
import traceback
from functools import wraps
from typing import Any, TypeVar, Union

from rucio.common.config import config_get
from rucio.common.exception import (
    AccessDenied,
    DataIdentifierAlreadyExists,
    DataIdentifierNotFound,
    DuplicateContent,
    InvalidObject,
    InvalidRSEExpression,
    MissingDependency,
    RSENotFound,
    RucioException,
    RuleNotFound,
    UnsupportedOperation,
)
from rucio.common.utils import extract_scope

MultiOutType = TypeVar("MultiOutType", dict[str, Any], list[dict[str, Any]])


def get_dids(dids: Union[str, list[str]], client) -> list[dict[str, str]]:
    """
    Helper function to ensure a replica exists before streaming
    """
    existing_dids = []
    if isinstance(dids, str):
        dids = [dids]
    for did in dids:
        scope, name = get_scope(did, client)
        existing_dids.append({"scope": scope, "name": name})

    return existing_dids


def resolve_to_contents(scope: str, name: str, client, original_level: str = "CONTAINER", resolve_to: str = "DATASET"):
    """
    Helper function to resolve a dataset or container to its contents.
    """
    datasets = []
    for did in client.list_content(scope, name):
        if did["type"] == resolve_to:
            datasets.append({"scope": did["scope"], "name": did["name"]})

        elif did["type"] == original_level:
            datasets.extend(resolve_to_contents(did["scope"], did["name"], client, original_level, resolve_to))
    return datasets


def get_scope(did: str, client):
    try:
        scope, name = extract_scope(did)
        return scope, name
    except TypeError:
        scopes = client.list_scopes()
        scope, name = extract_scope(did, scopes)
        return scope, name


def exception_handler(function, logger):
    @wraps(function)
    def new_funct(*args, **kwargs):
        SUCCESS = 0
        FAILURE = 1

        try:
            return SUCCESS, function(*args, **kwargs)
        except NotImplementedError as error:
            logger.error(f"Cannot run that operation/command combination {error}")
            return FAILURE, None
        except InvalidObject as error:
            logger.error(error)
            return error.error_code, None
        except DataIdentifierNotFound as error:
            logger.error(error)
            logger.debug("This means that the Data IDentifier you provided is not known by Rucio.")
            return error.error_code, None
        except AccessDenied as error:
            logger.error(error)
            logger.debug("This error is a permission issue. You cannot run this command with your account.")
            return error.error_code, None
        except DataIdentifierAlreadyExists as error:
            logger.error(error)
            logger.debug("This means that the Data IDentifier you try to add is already registered in Rucio.")
            return error.error_code, None
        except RSENotFound as error:
            logger.error(error)
            logger.debug("This means that the Rucio Storage Element you provided is not known by Rucio.")
            return error.error_code, None
        except InvalidRSEExpression as error:
            logger.error(error)
            logger.debug("This means the RSE expression you provided is not syntactically correct.")
            return error.error_code, None
        except DuplicateContent as error:
            logger.error(error)
            logger.debug("This means that the DID you want to attach is already in the target DID.")
            return error.error_code, None
        except TypeError as error:
            logger.error(error)
            logger.debug("This means the parameter you passed has a wrong type.")
            return FAILURE, None
        except RuleNotFound as error:
            logger.error(error)
            logger.debug("This means the rule you specified does not exist.")
            return error.error_code, None
        except UnsupportedOperation as error:
            logger.error(error)
            logger.debug("This means you cannot change the status of the DID.")
            return error.error_code, None
        except MissingDependency as error:
            logger.error(error)
            logger.debug("This means one dependency is missing.")
            return error.error_code, None
        except KeyError as error:
            if "x-rucio-auth-token" in str(error):
                used_account = None
                try:  # get the configured account from the configuration file
                    used_account = "%s (from rucio.cfg)" % config_get("client", "account")
                except:
                    pass
                try:  # are we overriden by the environment?
                    used_account = "%s (from RUCIO_ACCOUNT)" % os.environ["RUCIO_ACCOUNT"]
                except:
                    pass
                logger.error("Specified account %s does not have an associated identity." % used_account)
            else:
                logger.debug(traceback.format_exc())
                contact = config_get("policy", "support", raise_exception=False)
                support = ("Please follow up with all relevant information at: " + contact) if contact else ""
                logger.error("\nThe object is missing this property: %s\n" 'This should never happen. Please rerun the last command with the "-v" option to gather more information.\n' "%s" % (str(error), support))
            return FAILURE, None
        except RucioException as error:
            logger.error(error)
            return error.error_code, None
        except Exception as error:
            if isinstance(error, IOError) and getattr(error, "errno", None) == errno.EPIPE:
                # Ignore Broken Pipe
                # While in python3 we can directly catch 'BrokenPipeError', in python2 it doesn't exist.

                # Python flushes standard streams on exit; redirect remaining output
                # to devnull to avoid another BrokenPipeError at shutdown
                devnull = os.open(os.devnull, os.O_WRONLY)
                os.dup2(devnull, sys.stdout.fileno())
                return SUCCESS, None
            logger.debug(traceback.format_exc())
            logger.error(error)
            contact = config_get("policy", "support", raise_exception=False)
            support = ("If it's a problem concerning your experiment or if you're unsure what to do, please follow up at: %s\n" % contact) if contact else ""
            contact = config_get("policy", "support_rucio", default="https://github.com/rucio/rucio/issues")
            support += "If you're sure there is a problem with Rucio itself, please follow up at: " + contact
            logger.error("\nRucio exited with an unexpected/unknown error.\n" 'Please rerun the last command with the "-v" option to gather more information.\n' "%s" % support)
            return FAILURE, None

    return new_funct
