# -*- coding: utf-8 -*-
# Copyright 2021 CERN
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
# - Joel Dierkes <joel.dierkes@cern.ch>, 2021

from __future__ import absolute_import

import functools
import logging
import os

from rucio.common.config import config_get


def get_log_level(verbose):
    """
    Returns the log level of the application.

    :param verbose: If set, return 'DEBUG'.
    :returns: The log level to use for the applicaiton.
    """
    if verbose:
        return logging.getLevelName('DEBUG')

    if 'RUCIO_LOGGING_LEVEL' in os.environ:
        return logging.getLevelName(os.environ['RUCIO_LOGGING_LEVEL'].upper())

    return logging.getLevelName(config_get('common', 'loglevel', raise_exception=False, default='INFO').upper())


def create_log_format_handler():
    """
    Creates a :ref:logging.Formatter: object with the respective format string.

    Format string priority (except debug level):
        1. os.environ['RUCIO_LOGGING_FORMAT']
        2. Config file '[common] logformat = ...'
        3. Default value

    :param format: The format string to use.
    :returns: A handler object for a :ref:logging.Logger: object.
    """
    logformat = config_get('common', 'logformat', raise_exception=False, default='%(asctime)s\t%(levelname)s\t%(message)s')

    if 'RUCIO_LOGGING_FORMAT' in os.environ:
        # Override with env variable if present
        logformat = os.environ['RUCIO_LOGGING_FORMAT']

    handler = logging.StreamHandler()

    def emit_decorator(fnc):
        def func(*args):
            logcolor = '\033[36;1m'
            tmplogformat = logformat
            levelno = args[0].levelno
            if levelno >= logging.ERROR:
                logcolor = '\033[31;1m'
            elif levelno >= logging.WARNING:
                logcolor = '\033[33;1m'
            elif levelno >= logging.INFO:
                logcolor = '\033[32;1m'
                tmplogformat = '%(asctime)s\t%(levelname)s\t%(filename)s\t%(lineno)d\t%(message)s'
            formatter = logging.Formatter('{}{}\033[0m'.format(logcolor, tmplogformat))

            handler.setFormatter(formatter)
            return fnc(*args)
        return func

    handler.emit = emit_decorator(handler.emit)
    return handler


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


def setup_logger(module_name="usr", verbose=False):
    '''
    Factory method to set logger with handlers.
    :param module_name: __name__ of the module that is calling this method
    :param logger_name: name of the logger, typically name of the module.
    :param logger_level: if not given, fetched from config.
    :param verbose: verbose option set in bin/rucio
    '''
    logger = logging.getLogger(module_name.split(',')[-1])
    logger.setLevel(get_log_level(verbose))
    logger.addHandler(create_log_format_handler())

    return logger
