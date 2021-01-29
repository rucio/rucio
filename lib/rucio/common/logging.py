# -*- coding: utf-8 -*-
# Copyright 2012-2021 CERN
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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2021
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2021

from __future__ import absolute_import

import functools
import logging
import sys

from rucio.common.config import config_get


def setup_logging():
    """
    Configures the logging by setting the output stream to stdout and
    configures log level and log format.
    """
    config_loglevel = getattr(logging, config_get('common', 'loglevel', raise_exception=False, default='DEBUG').upper())
    config_logformat = config_get('common', 'logformat', raise_exception=False, default='%(asctime)s\t%(name)s\t%(process)d\t%(levelname)s\t%(message)s')

    logging.basicConfig(stream=sys.stdout,
                        level=config_loglevel,
                        format=config_logformat)


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
