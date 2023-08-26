# -*- coding: utf-8 -*-
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
import datetime
import functools
import itertools
import json
import logging
import re
import sys
from collections.abc import Callable, Iterator, Mapping, Sequence
from traceback import format_tb
from typing import TYPE_CHECKING, Any, Optional

from rucio.common.config import config_get, config_get_bool

if TYPE_CHECKING:
    from logging import LogRecord


# Mapping from ECS field paths
# https://www.elastic.co/guide/en/ecs-logging/overview/current/intro.html#_field_mapping
# https://www.elastic.co/guide/en/ecs/8.5/ecs-field-reference.html
# to python log record attributes:
# https://docs.python.org/3/library/logging.html#logrecord-attributes
BUILTIN_FIELDS = (
    ('@timestamp', 'asctime'),
    ('message', 'message'),
    ('log.level', 'levelname'),
    ('log.origin.function', 'funcName'),
    ('log.origin.file.line', 'lineno'),
    ('log.origin.file.name', 'filename'),
    ('log.logger', 'name'),
    ('process.pid', 'process'),
    ('process.name', 'processName'),
    ('process.thread.id', 'thread'),
    ('process.thread.name', 'threadName'),
)
ECS_TO_LOG_RECORD_MAP = dict(BUILTIN_FIELDS)
LOG_RECORD_TO_ECS_MAP = dict((f[1], f[0]) for f in BUILTIN_FIELDS)


def _json_serializable(obj: Any):
    try:
        return obj.__dict__
    except AttributeError:
        return str(obj)


def _navigate_path(obj: Any, path: Sequence[str]) -> Optional[Any]:
    """
    Traverse the path in the given object either via attributes or via dict-like subscriptions.
    Returns the found value; None if navigation fails

    For example, for an input
      obj = request  # flask "request" object https://flask.palletsprojects.com/en/2.1.x/api/#flask.Request
      path = ['headers', 'X-Rucio-Auth-Token']
    returns the value found in
      request.headers['X-Rucio-Auth-Token']
    """
    value = obj
    i = 0
    while value and i < len(path):
        p = path[i]
        try:
            value = getattr(value, p)
        except AttributeError:
            try:
                # Allow integers for access into arrays
                p = int(p)
            except ValueError:
                pass
            try:
                value = value[p]
            except (TypeError, KeyError):
                value = None
        i += 1
    if value is obj:
        return None
    return value


def _unflatten_dict(dictionary: dict[str, Any]) -> dict[str, Any]:
    """
    Transform a dict of the form
    {'a.b.c': value1, 'a.b.d': value2, 'z': value3}
    into
    {'a': {'b': {'c': value1, 'd': value2}}, 'z': value3}

    On incompatible input keys (for example: 'a.b.c', 'a', 'a.d'), the last key wins
    """
    ret = {}
    for k, v in dictionary.items():
        path = k.split('.')
        d = ret
        i = 0
        while i < len(path) - 1:
            existing_v = d.get(path[i])
            if isinstance(existing_v, dict):
                d = existing_v
            else:
                d[path[i]] = {}
                d = d[path[i]]
            i += 1
        if i == len(path) - 1:
            d[path[i]] = v
    return ret


def _get_request_data(request_path: Sequence[str]) -> "Callable[[LogDataSource, LogRecord], Iterator[tuple[str, Optional[Any]]]]":
    """
    Returns a function which, when called, will resolve the value
    in the flask request object at request_path
    """

    # The import fails if imported inside a client due to rsemanager.
    # TODO: move to top of file once we got rid of/refactored rsemanager
    from flask import has_request_context, request

    def _request_data_formatter(record_formatter: "LogDataSource", record: "LogRecord") -> Iterator[tuple[str, Optional[Any]]]:
        value = None
        if has_request_context() and request_path:
            value = _navigate_path(request, request_path)
        yield record_formatter.ecs_fields[0], str(value) if value is not None else None

    return _request_data_formatter


def _get_record_attribute(attribute: str) -> "Callable[[LogDataSource, LogRecord], Iterator[tuple[str, Optional[Any]]]]":
    """
    Returns a function which, when called, will generate the value of the desired attribute from
    the record passed in argument.
    """

    def _record_attribute_formatter(record_formatter: "LogDataSource", record: "LogRecord") -> Iterator[tuple[str, Optional[Any]]]:
        value = None
        try:
            value = getattr(record, attribute)
        except AttributeError:
            pass
        yield record_formatter.ecs_fields[0], value

    return _record_attribute_formatter


def _timestamp_formatter(record_formatter: "LogDataSource", record: "LogRecord") -> Iterator[tuple[str, Optional[Any]]]:
    """
    Format a timestamp
    """
    yield record_formatter.ecs_fields[0], datetime.datetime.utcfromtimestamp(record.created).isoformat(timespec='milliseconds') + 'Z'


def _ecs_field_to_record_attribute(field_name):
    """
    Sanitize the path-like field name into a symbol which can be the name of an object attribute.
    """
    record = ECS_TO_LOG_RECORD_MAP.get(field_name)
    if record:
        return record
    return field_name.replace('-', '_').replace('.', '_')


class LogDataSource:
    """
    Represents one log data source and allows to format it into one or more json fields
    """
    def __init__(
            self,
            ecs_fields: tuple[str, ...],
            formatter: "Optional[Callable[[LogDataSource, LogRecord], Iterator[tuple[str, Optional[Any]]]]]" = None,
            dst_record_attr: Optional[str] = None
    ):
        self.ecs_fields = ecs_fields
        self._formatter = formatter
        self._dst_record_attr = dst_record_attr

    def __hash__(self):
        return hash(self.ecs_fields)

    def __eq__(self, other: Any):
        if not other or not isinstance(other, self.__class__):
            return False
        return self.ecs_fields == other.ecs_fields

    def __str__(self):
        return self.__class__.__name__ + '(' + ', '.join(self.ecs_fields) + ')'

    def format(self, record: "LogRecord"):
        if not self._formatter:
            return
        for field_name, field_value in self._formatter(self, record):
            if self._dst_record_attr:
                setattr(record, self._dst_record_attr, field_value)
            yield field_name, field_value


class MessageLogDataSource(LogDataSource):
    def __init__(self):
        super().__init__(
            ecs_fields=('message', 'error.type', 'error.message', 'error.stack_trace'),
            formatter=None,
        )

    @staticmethod
    def _get_exc_info(record):
        exc_info = record.exc_info
        if not exc_info:
            return None
        if isinstance(exc_info, bool):
            exc_info = sys.exc_info()
        if isinstance(exc_info, (list, tuple)):
            return exc_info
        return None

    def format(self, record: "LogRecord"):
        exc_info = self._get_exc_info(record)
        message = record.getMessage()
        error_type, error_message, stack_trace = None, None, None
        if exc_info:
            error_type = exc_info[0].__name__ if exc_info[0] else None
            error_message = str(exc_info[1]) if exc_info[1] else None
            stack_trace = "".join(format_tb(record.exc_info[2])) or None if exc_info[2] else None
            if not stack_trace:
                stack_trace = str(getattr(record, "stack_info", '')) or None

        # Set the message into the record field
        s = message
        if error_message:
            if s[-1:] != "\n":
                s = s + "\n"
            s = s + error_message
        if stack_trace:
            if s[-1:] != "\n":
                s = s + "\n"
            s = s + stack_trace
        record.message = s

        yield from zip(self.ecs_fields, (record.message, error_type, error_message, stack_trace))


class ConstantStrDataSource(LogDataSource):
    """
    Prints a constant string for the given ECS field.
    """

    def __init__(self, ecs_field, _str):
        log_record = ECS_TO_LOG_RECORD_MAP.get(ecs_field, None)
        self._str = _str

        def _formatter(data_source: LogDataSource, record: "LogRecord"):
            yield self.ecs_fields[0], self._str

        super().__init__(ecs_fields=(ecs_field,), formatter=_formatter, dst_record_attr=log_record)


class RucioFormatter(logging.Formatter):
    """
    The formatter should be a drop-in replacement to the python builtin
    formatter, with two additional additions:
    - it can output directly to json
    - it can include data from the flask 'request' object into the format

    When the logger writes to a json format, it tries to respect the
    Elastic Common Schema (ECS) specification, but without getting too
    strict about it.

    When the format string contains a dot-separated "path" starting with
    `http.request.`, the rucio formatter will try to extract the given
    path from the flask `request` object.
    """

    def __init__(
            self,
            fmt: Optional[str] = None,
            validate: Optional[bool] = None,
            output_json: bool = False,
            additional_fields: Optional[Mapping[str, str]] = None
    ):
        _kwargs = {}
        if validate is not None:
            _kwargs["validate"] = validate

        data_sources: dict[str, LogDataSource] = dict(
            (ecs_field, LogDataSource((ecs_field,), formatter=_get_record_attribute(log_record)))
            for ecs_field, log_record in BUILTIN_FIELDS
        )
        data_sources.update({
            '@timestamp': LogDataSource(('@timestamp',), formatter=_timestamp_formatter),
            'message': MessageLogDataSource(),  # ('message', 'error.type', 'error.message', 'error.stack_trace'),
        })
        data_sources.update(
            (ecs_field, LogDataSource((ecs_field,),
                                      dst_record_attr=_ecs_field_to_record_attribute(ecs_field),
                                      formatter=_get_request_data(request_path=request_path.split('.'))))
            for ecs_field, request_path in (
                ('client.account.name', 'headers.X-Rucio-Account'),  # this field is rucio-specific, not from the ECS specification
                ('network.forwarded_ip', 'access_route.0'),
                ('source.ip', 'remote_addr'),
                ('url.full', 'url'),
                ('user_agent.original', 'user_agent'),
            )
        )
        if additional_fields:
            data_sources.update({
                ecs_field: ConstantStrDataSource(ecs_field, field_value)
                for ecs_field, field_value in additional_fields.items()
            })

        self._desired_data_sources = []
        if fmt:
            # extract of field1, field2 from the printf format-string "%(field1)s %(field2)i"
            # Allow simple path-like structures in fields (words separated with dots):
            # - http.request.headers.X-Rucio-Auth-Token
            # - http.request.url
            _format_string_fields = set(t[0] for t in re.findall(r'%\((\w+(.\w+(-\w+)*)*)\)', fmt))

            for field_name in _format_string_fields:
                data_source = data_sources.get(LOG_RECORD_TO_ECS_MAP.get(field_name, field_name), None)

                if '.' in field_name:
                    dst_record_attr = _ecs_field_to_record_attribute(field_name)
                    fmt = fmt.replace(f'%({field_name})', f'%({dst_record_attr})')
                    if field_name.startswith('http.request.'):
                        path = field_name.replace('http.request.', '', 1).split('.')
                        data_source = LogDataSource((field_name,), dst_record_attr=dst_record_attr, formatter=_get_request_data(path))
                elif not data_source:
                    data_source = LogDataSource((field_name,), formatter=_get_record_attribute(field_name))

                if data_source:
                    self._desired_data_sources.append(data_source)
        else:
            self._desired_data_sources = [data_sources['message']]

        self.output_json = output_json
        super().__init__(fmt=fmt, style='%', **_kwargs)

    def format(self, record):
        json_record = dict(itertools.chain.from_iterable(f.format(record) for f in self._desired_data_sources))
        if self.output_json:
            return self._to_json(_unflatten_dict(json_record))
        else:
            return super().format(record)

    @staticmethod
    def _to_json(record):
        try:
            return json.dumps(record, default=_json_serializable)
        except (TypeError, ValueError, OverflowError):
            try:
                return json.dumps(record)
            except (TypeError, ValueError, OverflowError):
                return '{}'


def rucio_log_formatter(process_name: Optional[str] = None):
    config_logformat = config_get('common', 'logformat', raise_exception=False, default='%(asctime)s\t%(name)s\t%(process)d\t%(levelname)s\t%(message)s')
    output_json = config_get_bool('common', 'logjson', default=False)
    additional_fields = {}
    if process_name:
        additional_fields['process.name'] = process_name
    return RucioFormatter(fmt=config_logformat, output_json=output_json, additional_fields=additional_fields)


def setup_logging(application=None, process_name=None):
    """
    Configures the logging by setting the output stream to stdout and
    configures log level and log format.
    """
    config_loglevel = getattr(logging, config_get('common', 'loglevel', raise_exception=False, default='DEBUG').upper())

    stdouthandler = logging.StreamHandler(stream=sys.stdout)
    stdouthandler.setFormatter(rucio_log_formatter(process_name=process_name))
    stdouthandler.setLevel(config_loglevel)
    logging.basicConfig(level=config_loglevel, handlers=[stdouthandler])

    if application:
        application.logger.addHandler(stdouthandler)


def formatted_logger(innerfunc, formatstr="%s"):
    """
    Decorates the passed function, formatting log input by
    the passed formatstr. The format string must always include a %s.

    :param innerfunc: function to be decorated. Must take (level, msg) arguments.
    :type innerfunc: Callable
    :param formatstr: format string with %s as placeholder.
    :type formatstr: str
    """
    @functools.wraps(innerfunc)
    def log_format(level, msg, *args, **kwargs):
        return innerfunc(level, formatstr % msg, *args, **kwargs)
    return log_format
