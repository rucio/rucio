# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012

"""
Get the configuration file from /opt/rucio/etc/rucio.cfg
If it is not there, get it from $RUCIO_HOME
If it is not there, except.
"""

import os

import ConfigParser


def config_get(section, option):
    """Return the string value for a given option in a section"""
    return __config.get(section, option)


def config_get_int(section, option):
    """Return the integer value for a given option in a section"""
    return __config.get(section, option)


def config_get_float(section, option):
    """Return the floating point value for a given option in a section"""
    return __config.getfloat(section, option)


def config_get_bool(section, option):
    """Return the boolean value for a given option in a section"""
    return __config.getboolean(section, option)


__config = ConfigParser.ConfigParser()

__configfile = '/opt/rucio/etc/rucio.cfg'
__validate = __config.read(__configfile)

if __validate != [__configfile]:
    if 'RUCIO_HOME' in os.environ:
        __configfile = '%s/etc/rucio.cfg' % os.environ['RUCIO_HOME']
        __validate = __config.read(__configfile)

    if 'VIRTUAL_ENV' in os.environ:
        __configfile = '%s/etc/rucio.cfg' % os.environ['VIRTUAL_ENV']
        __validate = __config.read(__configfile)

    if __validate != [__configfile]:
        raise Exception('Could not load /opt/rucio/etc/rucio.cfg and RUCIO_HOME is not set.')
