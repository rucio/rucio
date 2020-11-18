# -*- coding: utf-8 -*-
# Copyright 2020 CERN
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
#
# Authors:
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

import six
from flask import Response
from web import HTTPError
from werkzeug.datastructures import Headers

from rucio.common.utils import codes, render_json


def _error_response(exc_cls, exc_msg):
    def strip_newlines(msg):
        if msg is None:
            return None
        elif isinstance(msg, six.binary_type):
            msg = six.ensure_text(msg, errors='replace')
        elif not isinstance(msg, six.string_types):
            # any objects will be converted to their string representation in unicode
            msg = six.ensure_text(str(msg), errors='replace')
        return msg.replace('\n', ' ').replace('\r', ' ')

    data = {'ExceptionClass': exc_cls,
            'ExceptionMessage': exc_msg}

    exc_msg = strip_newlines(exc_msg)
    if exc_msg:
        # Truncate too long exc_msg
        oldlen = len(exc_msg)
        exc_msg = exc_msg[:min(oldlen, 125)]
        if len(exc_msg) != oldlen:
            exc_msg = exc_msg + '...'
    headers = {'Content-Type': 'application/octet-stream',
               'ExceptionClass': strip_newlines(exc_cls),
               'ExceptionMessage': exc_msg}

    return data, headers


def generate_http_error(status_code, exc_cls, exc_msg):
    """
    utitily function to generate a complete HTTP error response.
    :param status_code: The HTTP status code to generate a response for.
    :param exc_cls: The name of the exception class to send with the response.
    :param exc_msg: The error message.
    :returns: a web.py HTTP response object.
    """
    data, headers = _error_response(exc_cls, exc_msg)
    try:
        return HTTPError(status=codes[status_code], headers=headers, data=render_json(**data))
    except Exception:
        print(data)
        raise


def generate_http_error_flask(status_code, exc_cls, exc_msg, headers=None):
    """
    utitily function to generate a complete HTTP error response.
    :param status_code: The HTTP status code to generate a response for.
    :param exc_cls: The name of the exception class to send with the response.
    :param exc_msg: The error message.
    :returns: a Flask HTTP response object.
    :param headers: any default headers to send along.
    """
    data, prioheaders = _error_response(exc_cls, exc_msg)
    headers = Headers(headers)
    headers.extend(prioheaders)
    try:
        return Response(status=status_code, headers=headers, content_type=prioheaders['Content-Type'], response=render_json(**data))
    except Exception:
        print(data)
        raise
