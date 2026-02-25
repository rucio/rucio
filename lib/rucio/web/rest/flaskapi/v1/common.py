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

import itertools
import json
import logging
import os
import re
from configparser import NoOptionError, NoSectionError
from functools import wraps
from time import time
from typing import TYPE_CHECKING, Any, Literal, Optional, TypeVar, Union, cast
from urllib.parse import unquote_plus

import flask
from flask.views import MethodView
from typing_extensions import ParamSpec
from werkzeug.datastructures import Headers
from werkzeug.exceptions import HTTPException
from werkzeug.wrappers import Request, Response

from rucio.common import config
from rucio.common.constants import DEFAULT_VO, HTTPMethod
from rucio.common.exception import CannotAuthenticate, DatabaseException, IdentityError, RucioException, UnsupportedRequestedContentType
from rucio.common.schema import get_schema_value
from rucio.common.utils import generate_uuid, render_json
from rucio.core.vo import map_vo
from rucio.gateway.authentication import validate_auth_token
from rucio.gateway.identity import get_default_account, list_accounts_for_identity, verify_identity

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from _typeshed import SupportsIter
    from _typeshed.wsgi import StartResponse, WSGIApplication, WSGIEnvironment
    from flask.typing import ResponseReturnValue

    from rucio.web.rest.flaskapi.v1.types import HeadersType

ResponseTypeVar = TypeVar('ResponseTypeVar', bound=flask.wrappers.Response)

RUCIO_HTTPD_ENCODED_SLASHES_NO_DECODE = os.environ.get('RUCIO_HTTPD_ENCODED_SLASHES_NO_DECODE',
                                                       'false').lower() == 'true'
_DEFAULT = object()


class CORSMiddleware:
    """
    WebUI 2.0 makes preflight requests to the API, which are not handled by the API.
    This middleware intercepts the preflight OPTIONS requests and returns a 200 OK response.
    """

    def __init__(self, app: 'WSGIApplication') -> None:
        self.app = app

    def __call__(self, environ: 'WSGIEnvironment', start_response: 'StartResponse') -> 'Iterable[bytes]':
        request: Request = Request(environ)

        if request.environ.get('REQUEST_METHOD') == HTTPMethod.OPTIONS.value:
            try:
                webui_urls = config.config_get_list('webui', 'urls')
            except (NoOptionError, NoSectionError, RuntimeError) as error:
                logging.exception('Could not get webui urls from config file')
                return str(error), 500  # type: ignore (return type incompatible with Flask middleware)
            if request.origin in webui_urls:
                response: Response = Response(status=200)
                response.headers['Access-Control-Allow-Origin'] = request.origin
                response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
                response.headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')  # type: ignore (value could be None)
                response.headers['Access-Control-Allow-Credentials'] = 'true'
                return response(environ, start_response)
            response: Response = Response(status=403)
            return response(environ, start_response)

        # bypass this middleware for non-OPTIONS requests
        return self.app(environ, start_response)


class ErrorHandlingMethodView(MethodView):
    """
    Special MethodView that handles generic RucioExceptions and more generic
    Exceptions for all defined methods automatically.
    """

    def get_headers(self) -> Optional['HeadersType']:
        """Can be overridden to add headers to generic error responses."""
        return None

    def dispatch_request(self, *args, **kwargs) -> Union['ResponseReturnValue', flask.wrappers.Response]:
        headers = self.get_headers() or None
        try:
            return super(ErrorHandlingMethodView, self).dispatch_request(*args, **kwargs)
        except HTTPException:
            raise
        except DatabaseException as error:
            if 'QueuePool' in str(error):
                msg = f'DatabaseException in {self.__class__.__module__} {self.__class__.__name__} {flask.request.method}'
                # logged, because this should be the __exception__
                logging.debug(msg, exc_info=True)
                return generate_http_error_flask(
                    status_code=503,
                    exc=error.__class__.__name__,
                    exc_msg=('Currently there are too many requests for the Rucio '
                             'servers to handle. Please try again in a few minutes.'),
                    headers=headers
                )
            else:
                msg = f'DatabaseException in {self.__class__.__module__} {self.__class__.__name__} {flask.request.method}'
                logging.debug(msg, exc_info=True)
                return generate_http_error_flask(
                    status_code=500,
                    exc=error.__class__.__name__,
                    exc_msg='An unknown Database Exception has occurred.',
                    headers=headers
                )

        except RucioException as error:
            # should be caught in the flask view and generate_http_error_flask with a proper HTTP status code returned
            msg = f'Uncaught RucioException in {self.__class__.__module__} {self.__class__.__name__} {flask.request.method}'
            # logged, because this should be the __exception__
            logging.debug(msg, exc_info=True)
            return generate_http_error_flask(
                status_code=500,
                exc=error.__class__.__name__,
                exc_msg=error.args[0],
                headers=headers
            )
        except Exception as error:
            # logged, because this means a programming error
            logging.exception("Internal Error")
            if headers:
                return str(error), 500, headers
            else:
                return str(error), 500


def request_auth_env() -> Optional['ResponseReturnValue']:
    if flask.request.environ.get('REQUEST_METHOD') == HTTPMethod.OPTIONS.value:
        return '', 200

    auth_token = flask.request.headers.get('X-Rucio-Auth-Token', default=None)

    if not auth_token:
        return generate_http_error_flask(400, ValueError.__name__, 'Token must be set.')

    try:
        auth = validate_auth_token(auth_token)
    except CannotAuthenticate:
        return generate_http_error_flask(401, CannotAuthenticate.__name__, 'Cannot authenticate with given credentials')
    except RucioException as error:
        return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
    except Exception:
        logging.exception('Internal error in validate_auth_token')
        return 'Internal Error', 500

    flask.request.environ['vo'] = auth.get('vo', DEFAULT_VO)
    flask.request.environ['issuer'] = auth.get('account')
    flask.request.environ['identity'] = auth.get('identity')
    flask.request.environ['request_id'] = generate_uuid()
    flask.request.environ['start_time'] = time()


def response_headers(response: ResponseTypeVar) -> ResponseTypeVar:
    response.headers['Access-Control-Allow-Origin'] = flask.request.environ.get('HTTP_ORIGIN')  # type: ignore (value could be None)
    response.headers['Access-Control-Allow-Headers'] = flask.request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')  # type: ignore (value could be None)
    response.headers['Access-Control-Allow-Methods'] = '*'
    response.headers['Access-Control-Allow-Credentials'] = 'true'

    if flask.request.environ.get('REQUEST_METHOD') == HTTPMethod.GET.value:
        response.headers['Cache-Control'] = 'no-cache, no-store, max-age=0, must-revalidate'
        response.headers['Cache-Control'] = 'post-check=0, pre-check=0'
        response.headers['Pragma'] = 'no-cache'

    return response


P = ParamSpec('P')
R = TypeVar('R')


def check_accept_header_wrapper_flask(
        supported_content_types: 'Iterable[str]'
) -> 'Callable[[Callable[P, R]], Callable[P, R]]':
    """Decorator that refuses requests with an unsupported *Accept* header."""

    def wrapper(
            f: 'Callable[P, R]'
    ) -> 'Callable[P, R]':
        """Decorate *f* with an *Accept*-header check and return the new callable."""

        @wraps(f)
        def decorated(*args: 'P.args', **kwargs: 'P.kwargs') -> 'R':
            """Run the header check, then delegate to *f* (or return 406)."""

            # 1. no Accept header → accept everything
            if not flask.request.accept_mimetypes.provided:
                return f(*args, **kwargs)

            # 2. at least one acceptable media‑type → call the view
            if any(s in flask.request.accept_mimetypes for s in supported_content_types):
                return f(*args, **kwargs)

            # 3. none matched → 406 response
            return cast(
                'R',
                generate_http_error_flask(
                    status_code=406,
                    exc=UnsupportedRequestedContentType.__name__,
                    exc_msg=(
                        f'The requested content type '
                        f'{flask.request.environ.get("HTTP_ACCEPT")} is not supported. '
                        f'Use {supported_content_types}.'
                    ),
                ),
            )

        return decorated

    return wrapper


def parse_scope_name(scope_name: str, vo: Optional[str]) -> tuple[str, ...]:
    """
    Parses the given scope_name according to the schema's
    SCOPE_NAME_REGEXP and returns a (scope, name) tuple.

    :param scope_name: the scope_name string to be parsed.
    :param vo: the vo currently in use.
    :raises ValueError: when scope_name could not be parsed.
    :returns: a (scope, name) tuple.
    """

    if RUCIO_HTTPD_ENCODED_SLASHES_NO_DECODE:
        if scope_name.count('/') != 1:
            # scope and name are always separated by a single slash ('/', unencoded) in the request.
            # If the server is configured with the 'NoDecode' option, other slashes will be encoded.
            # This is just a sanity check that should never happen.
            raise ValueError(f"Could not parse '{scope_name}' ({scope_name=}) with encoded '/' into scope and name.")

        scope, name = scope_name.split('/', 1)
        name = unquote_plus(name)

        return scope, name

    if not vo:
        vo = DEFAULT_VO

    # The ':' in DID is replaced by '/', also an '/' is added. Why?
    pattern = get_schema_value('SCOPE_NAME_REGEXP', vo)
    text = '/' + scope_name

    scope_regex = re.match(pattern, text)
    if scope_regex is None:
        raise ValueError(f"Could not parse '{text}' ({scope_name=}) with pattern '{pattern}' into scope and name.")

    scope, name = scope_regex.group(1, 2)
    return scope, name


def try_stream(
        generator: 'SupportsIter',
        content_type: Optional[str] = None
) -> flask.Response:
    """
    Peeks at the first element of the passed generator and raises
    an error, if yielding raises. Otherwise returns
    a flask.Response object.

    :param generator: a generator function or an iterator.
    :param content_type: the response's Content-Type.
                         'application/x-json-stream' by default.
    :returns: a response object with the specified Content-Type.
    """
    if not content_type:
        content_type = 'application/x-json-stream'

    it = iter(generator)
    try:
        peek = next(it)
        return flask.Response(flask.stream_with_context(itertools.chain((peek,), it)), content_type=content_type)
    except StopIteration:
        return flask.Response('', content_type=content_type)


def error_headers(exc_cls: str, exc_msg: str) -> dict[str, str]:
    def strip_newlines(msg: str) -> str:
        return msg.replace('\n', ' ').replace('\r', ' ')

    if exc_msg:
        exc_msg = strip_newlines(exc_msg)
        # Truncate too long exc_msg
        oldlen = len(exc_msg)
        exc_msg = exc_msg[:min(oldlen, 125)]
        if len(exc_msg) != oldlen:
            exc_msg = exc_msg + '...'
    return {
        'ExceptionClass': strip_newlines(exc_cls),
        'ExceptionMessage': exc_msg
    }


def _error_response(exc_cls: str, exc_msg: str) -> tuple[dict[str, str], dict[str, str]]:
    data = {'ExceptionClass': exc_cls,
            'ExceptionMessage': exc_msg}
    headers = {'Content-Type': 'application/octet-stream'}
    headers.update(error_headers(exc_cls=exc_cls, exc_msg=exc_msg))
    return data, headers


def generate_http_error_flask(
        status_code: int,
        exc: Union[str, BaseException],
        exc_msg: Optional[str] = None,
        headers: Optional['HeadersType'] = None,
) -> "flask.Response":
    """Utility function to generate a complete HTTP error response.

    :param status_code: The HTTP status code to generate a response for.
    :param exc: The name of the exception class or a RucioException object.
    :param exc_msg: The error message.
    :param headers: any default headers to send along.
    :returns: a response object representing the error.
    """
    if isinstance(exc, BaseException):
        if not exc_msg and exc.args and exc.args[0]:
            exc_msg = exc.args[0]
        exc_cls = exc.__class__.__name__
    else:
        exc_cls = str(exc)
    exc_msg = str(exc_msg)

    data, prioheaders = _error_response(exc_cls, exc_msg)
    headers = Headers(headers)
    headers.extend(prioheaders)
    try:
        return flask.Response(
            status=status_code,
            headers=headers,
            content_type=prioheaders['Content-Type'],
            response=render_json(**data),
        )
    except Exception:
        logging.exception('Cannot create generate_http_error_flask response with %s', data)
        raise


def json_parameters(json_loads: "Callable[[str], Any]" = json.loads, optional: bool = False) -> dict:
    """
    Returns the JSON parameters from the current request's body as dict.
    """
    if optional:
        kwargs = {'default': {}}
    else:
        kwargs = {}
    return json_parse(types=(dict, ), json_loads=json_loads, **kwargs)


def json_list(json_loads: "Callable[[str], Any]" = json.loads, optional: bool = False) -> list:
    """
    Returns the JSON array from the current request's body as list.
    """
    if optional:
        kwargs = {'default': []}
    else:
        kwargs = {}
    return json_parse(types=(list, ), json_loads=json_loads, **kwargs)


def json_parse(types: tuple, json_loads: "Callable[[str], Any]" = json.loads, **kwargs):
    def clstostr(cls) -> str:
        if cls.__name__ == "dict":
            return "dictionary"
        else:
            return cls.__name__

    def typestostr(_types: tuple) -> str:
        return " or ".join(map(clstostr, _types))

    data = flask.request.get_data(as_text=True)
    if 'default' in kwargs and not data:
        return kwargs['default']
    try:
        body = json_loads(data)
        if not isinstance(body, types):
            flask.abort(
                generate_http_error_flask(
                    status_code=400,
                    exc=TypeError.__name__,
                    exc_msg='body must be a json ' + typestostr(types)
                )
            )
        return body
    except json.JSONDecodeError:
        flask.abort(
            generate_http_error_flask(
                status_code=400,
                exc=ValueError.__name__,
                exc_msg='cannot decode json parameter ' + typestostr(types)
            )
        )


def param_get(parameters: dict[str, Any], name: str, default: Optional[Any] = _DEFAULT) -> Any:
    if default is not _DEFAULT:
        return parameters.get(name, default)
    else:
        if name not in parameters:
            flask.abort(
                generate_http_error_flask(
                    status_code=400,
                    exc=KeyError.__name__,
                    exc_msg=f"'{name}' not defined"
                )
            )
        return parameters[name]


def param_get_bool(parameters: dict[str, Any], name: str, default: Optional[bool] = None) -> bool:
    """
        Get a boolean parameter from the passed parameters. Converts to True/False.
    """
    def _str_to_bool(option: Union[str, bool]) -> bool:
        # TODO remove warning and replace with error in v40 - #8156
        try:
            int(option)
            logging.warning("Booleans should only accept true/false. Please change 0/1 to true/false.")
        except (TypeError, ValueError):
            pass

        if isinstance(option, int):
            option = f"{option}"

        if isinstance(option, bool):
            return option
        elif option.lower() in ['true', '1']:
            return True
        elif option.lower() in ['false', '0']:
            return False
        else:
            flask.abort(
                generate_http_error_flask(
                    status_code=400,
                    exc=TypeError.__name__,
                    exc_msg=f"'{name}' must be a boolean type."
                )
            )
    value = parameters.get(name, default)
    if value is None:
        flask.abort(
                generate_http_error_flask(
                    status_code=400,
                    exc=KeyError.__name__,
                    exc_msg=f"'{name}' not defined"
                )
            )
    return _str_to_bool(value)


def extract_vo(headers: Headers) -> str:
    """ Extract the VO name from the given request.headers object and
        does any name mapping. Returns the short VO name or raise a
        flask.abort if the VO name doesn't meet the name specification.

    :papam headers: The request.headers object for the current request.
    :returns: a string containing the short VO name.
    """
    try:
        return map_vo(headers.get('X-Rucio-VO', default=DEFAULT_VO))
    except RucioException as err:
        # VO Name doesn't match allowed spec
        flask.abort(generate_http_error_flask(status_code=400, exc=err))


def get_account_from_verified_identity(
        identity_key: str,
        id_type: Literal["USERPASS", "X509"],
        password: Optional[str] = None
) -> list[str]:
    """ Verifies the provided identity and tries to return a matching account.
        If no account is found, raises an IdentityError after trying to verify the identity.
        If multiple accounts are found, returns the default account if available, otherwise all accounts.
    :param identity_key: The identity key name. For example x509 DN, or a username.
    :param id_type: The type of the authentication (x509, USERPASS).
    :param password: required only if id_type==USERPASS.
    :raises IdentityError: if no account is found for the identity or if the identity could not be verified.
    :returns: a list of account names.
    """
    accounts = list_accounts_for_identity(identity_key=identity_key, id_type=id_type)
    if accounts is None or len(accounts) == 0:
        if id_type == 'USERPASS':
            verify_identity(identity_key=identity_key, id_type=id_type, password=password)
        elif id_type == 'X509':
            verify_identity(identity_key=identity_key, id_type=id_type)
        else:
            raise IdentityError('No account found for identity')
    if len(accounts) > 1:
        try:
            default_account = get_default_account(identity_key=identity_key, id_type=id_type)
            return [default_account]
        except IdentityError:
            return accounts
    else:
        account = accounts[0]
        return [account]
