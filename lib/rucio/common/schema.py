# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013

from json import loads
from jsonschema import validate, ValidationError

from rucio.common.config import get_schema_dir
from rucio.common.exception import ConfigurationError, InvalidObject


def get_schema(name):
    """
    Return the json schema for a specific name

    TODO: Memoize this method (cache, decorator, etc) to avoid i/o

    :param name: The json schema name.
    """
    try:
        schema_dir = get_schema_dir()  # NOQA
        match = '%(schema_dir)s/%(name)s.json' % locals()
        with open(match) as schema_file:
            return loads(schema_file.read())
    except IOError, e:
        if e[0] == 2:
            raise ConfigurationError('Could not find schema properties file %(schema_dir)s/%(name)s.json' % locals())
        raise


def validate_schema(name, obj):
    """
    Validate object against json schema

    :param name: The json schema name.
    :param obj: The object to validate.
    """
    try:
        validate(obj, get_schema(name))
    except ValidationError, e:  # NOQA
        raise InvalidObject("%(e)s" % locals())
