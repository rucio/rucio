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
import json
import logging
import os
import signal
import subprocess
import sys
import traceback
from configparser import NoOptionError, NoSectionError
from functools import wraps
from typing import Optional, Union

import click

from rucio.client.client import Client
from rucio.common.config import config_get
from rucio.common.exception import (
    AccessDenied,
    CannotAuthenticate,
    DataIdentifierAlreadyExists,
    DataIdentifierNotFound,
    Duplicate,
    DuplicateContent,
    InputValidationError,
    InvalidRSEExpression,
    MissingDependency,
    RSENotFound,
    RucioException,
    RuleNotFound,
    UnsupportedOperation,
)
from rucio.common.utils import setup_logger

SUCCESS = 0
FAILURE = 1


def exception_handler(function):
    verbosity = ("-v" in sys.argv) or ("--verbose" in sys.argv)
    logger = setup_logger(module_name=__name__, logger_name="user", verbose=verbosity)

    @wraps(function)
    def new_funct(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except InputValidationError as error:
            logger.error(error)
            logger.debug("This means that one you provided an invalid combination of parameters, or incorrect types. Please check the command help (-h/--help).")
            return FAILURE
        except NotImplementedError as error:
            logger.error(f"Cannot run that operation/command combination {error}")
            return FAILURE
        except DataIdentifierNotFound as error:
            logger.error(error)
            logger.debug("This means that the Data IDentifier you provided is not known by Rucio.")
            return error.error_code
        except AccessDenied as error:
            logger.error(error)
            logger.debug("This error is a permission issue. You cannot run this command with your account.")
            return error.error_code
        except DataIdentifierAlreadyExists as error:
            logger.error(error)
            logger.debug("This means that the Data IDentifier you try to add is already registered in Rucio.")
            return error.error_code
        except RSENotFound as error:
            logger.error(error)
            logger.debug("This means that the Rucio Storage Element you provided is not known by Rucio.")
            return error.error_code
        except InvalidRSEExpression as error:
            logger.error(error)
            logger.debug("This means the RSE expression you provided is not syntactically correct.")
            return error.error_code
        except DuplicateContent as error:
            logger.error(error)
            logger.debug("This means that the DID you want to attach is already in the target DID.")
            return error.error_code
        except Duplicate as error:
            logger.error(error)
            logger.debug("This means that you are trying to add something that already exists.")
            return error.error_code
        except TypeError as error:
            logger.error(error)
            logger.debug("This means the parameter you passed has a wrong type.")
            return FAILURE
        except RuleNotFound as error:
            logger.error(error)
            logger.debug("This means the rule you specified does not exist.")
            return error.error_code
        except UnsupportedOperation as error:
            logger.error(error)
            logger.debug("This means you cannot change the status of the DID.")
            return error.error_code
        except MissingDependency as error:
            logger.error(error)
            logger.debug("This means one dependency is missing.")
            return error.error_code
        except KeyError as error:
            if "x-rucio-auth-token" in str(error):
                used_account = None
                try:  # get the configured account from the configuration file
                    used_account = "%s (from rucio.cfg)" % config_get("client", "account")
                except Exception:
                    pass
                try:  # are we overriden by the environment?
                    used_account = "%s (from RUCIO_ACCOUNT)" % os.environ["RUCIO_ACCOUNT"]
                except Exception:
                    pass
                logger.error("Specified account %s does not have an associated identity." % used_account)

            else:
                logger.debug(traceback.format_exc())
                contact = config_get("policy", "support", raise_exception=False)
                support = ("Please follow up with all relevant information at: " + contact) if contact else ""
                logger.error("\nThe object is missing this property: %s\n" 'This should never happen. Please rerun the last command with the "-v" option to gather more information.\n' "%s" % (str(error), support))
            return FAILURE
        except RucioException as error:
            logger.error(error)
            return error.error_code
        except Exception as error:
            if isinstance(error, IOError) and getattr(error, "errno", None) == errno.EPIPE:
                # Ignore Broken Pipe
                # While in python3 we can directly catch 'BrokenPipeError', in python2 it doesn't exist.

                # Python flushes standard streams on exit; redirect remaining output
                # to devnull to avoid another BrokenPipeError at shutdown
                devnull = os.open(os.devnull, os.O_WRONLY)
                os.dup2(devnull, sys.stdout.fileno())
                return SUCCESS
            logger.debug(traceback.format_exc())
            logger.error(error)
            contact = config_get("policy", "support", raise_exception=False)
            support = ("If it's a problem concerning your experiment or if you're unsure what to do, please follow up at: %s\n" % contact) if contact else ""
            contact = config_get("policy", "support_rucio", default="https://github.com/rucio/rucio/issues")
            support += "If you're sure there is a problem with Rucio itself, please follow up at: " + contact
            logger.error("\nRucio exited with an unexpected/unknown error.\n" 'Please rerun the last command with the "-v" option to gather more information.\n' "%s" % support)
            return FAILURE

    return new_funct


def get_client(args, logger):
    """
    Returns a new client object.
    """
    if hasattr(args, "config") and (args.config is not None):
        os.environ["RUCIO_CONFIG"] = args.config

    if logger is None:
        logger = setup_logger(module_name=__name__, logger_name="user", verbose=args.verbose)

    if not args.auth_strategy:
        if "RUCIO_AUTH_TYPE" in os.environ:
            auth_type = os.environ["RUCIO_AUTH_TYPE"].lower()
        else:
            try:
                auth_type = config_get("client", "auth_type").lower()
            except (NoOptionError, NoSectionError):
                logger.error("Cannot get AUTH_TYPE")
                sys.exit(1)
    else:
        auth_type = args.auth_strategy.lower()

    if auth_type in ["userpass", "saml"] and args.username is not None and args.password is not None:
        creds = {"username": args.username, "password": args.password}
    elif auth_type == "oidc":
        if args.oidc_issuer:
            args.oidc_issuer = args.oidc_issuer.lower()
        creds = {
            "oidc_auto": args.oidc_auto,
            "oidc_scope": args.oidc_scope,
            "oidc_audience": args.oidc_audience,
            "oidc_polling": args.oidc_polling,
            "oidc_refresh_lifetime": args.oidc_refresh_lifetime,
            "oidc_issuer": args.oidc_issuer,
            "oidc_username": args.oidc_username,
            "oidc_password": args.oidc_password,
        }
    elif auth_type == "x509":
        creds = {"client_cert": args.certificate, "client_key": args.client_key}
    else:
        creds = None

    try:
        client = Client(rucio_host=args.host, auth_host=args.auth_host, account=args.issuer, auth_type=auth_type, creds=creds, ca_cert=args.ca_certificate, timeout=args.timeout, user_agent=args.user_agent, vo=args.vo, logger=logger)
    except CannotAuthenticate as error:
        logger.error(error)
        if "alert certificate expired" in str(error):
            logger.error("The server certificate expired.")
        elif auth_type.lower() == "x509_proxy":
            logger.error("Please verify that your proxy is still valid and renew it if needed.")
        sys.exit(1)
    return client


def signal_handler(sig, frame, logger):
    logger.warning("You pressed Ctrl+C! Exiting gracefully")
    child_processes = subprocess.Popen("ps -o pid --ppid %s --noheaders" % os.getpid(), shell=True, stdout=subprocess.PIPE)
    child_processes = child_processes.stdout.read()  # type: ignore
    for pid in child_processes.split("\n")[:-1]:  # type: ignore
        try:
            os.kill(int(pid), signal.SIGTERM)
        except Exception:
            print("Cannot kill child process")
    sys.exit(1)


def setup_gfal2_logger():
    gfal2_logger = logging.getLogger("gfal2")
    gfal2_logger.setLevel(logging.CRITICAL)
    gfal2_logger.addHandler(logging.StreamHandler())


class Arguments(dict):
    """dot.notation access to dictionary attributes"""

    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


class JSONType(click.ParamType):
    name = "json"

    def convert(
            self,
            value: Union[str, None],
            param: "Optional[click.Parameter]",
            ctx: "Optional[click.Context]",
    ) -> Optional[dict]:
        if value is None:
            return None

        try:
            return json.loads(value)
        except json.JSONDecodeError as e:
            self.fail(f"Invalid JSON: {e}", param, ctx)
