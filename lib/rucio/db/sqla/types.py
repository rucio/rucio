# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2018
#
# PY3K COMPATIBLE

import uuid

from six import string_types

from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.dialects.oracle import RAW, CLOB
from sqlalchemy.dialects.mysql import BINARY
from sqlalchemy.types import TypeDecorator, CHAR, String
import sqlalchemy.types as types


class GUID(TypeDecorator):
    """
    Platform-independent GUID type.

    Uses PostgreSQL's UUID type,
    uses Oracle's RAW type,
    uses MySQL's BINARY type,
    otherwise uses CHAR(32), storing as stringified hex values.

    """
    impl = CHAR

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(UUID())
        elif dialect.name == 'oracle':
            return dialect.type_descriptor(RAW(16))
        elif dialect.name == 'mysql':
            return dialect.type_descriptor(BINARY(16))
        else:
            return dialect.type_descriptor(CHAR(32))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == 'postgresql':
            return str(value).lower()
        elif dialect.name == 'oracle':
            return uuid.UUID(value).bytes
        elif dialect.name == 'mysql':
            return uuid.UUID(value).bytes
        else:
            if not isinstance(value, uuid.UUID):
                return "%.32x" % uuid.UUID(value)
            else:
                # hexstring
                return "%.32x" % value

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == 'oracle':
            return str(uuid.UUID(bytes=value)).replace('-', '').lower()
        elif dialect.name == 'mysql':
            return str(uuid.UUID(bytes=value)).replace('-', '').lower()
        else:
            return str(uuid.UUID(value)).replace('-', '').lower()


class BooleanString(TypeDecorator):
    """
    Encode True/False/String in a VARCHAR type for all databases.
    """

    impl = String

    def load_dialect_imp(self, dialect):
        return dialect.type_descriptor(String(255))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value

        # handle booleans always as lowercase string 'true'/'false'
        if isinstance(value, bool):
            if value:
                return 'true'
            return 'false'
        elif isinstance(value, string_types):
            if value.lower() == 'true':
                return 'true'
            elif value.lower() == 'false':
                return 'false'
            # FIXME
            # ATLAS RSE listing workaround (since booleans are capital 'True'/'False')
            # remove elif branch after appropriate database fix has been applied
            # see also core/rse.py
            elif value.startswith('tmp_atlas_'):
                return value[10:]

        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value

        # FIXME
        # be backward compatible for now by still including 0/1 as acceptable booleans
        # remove 0/1 after appropriate database fix has been applied
        if value.lower() in ['1', 'true']:
            return True
        elif value.lower() in ['0', 'false']:
            return False
        else:
            return value


class JSON(TypeDecorator):
    """
    Platform independent json type

    JSONB for postgres , JSON for the rest
    """

    impl = types.JSON

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(JSONB())
        elif dialect.name == 'mysql':
            return dialect.type_descriptor(types.JSON())
        elif dialect.name == 'oracle':
            return dialect.type_descriptor(CLOB())
        else:
            return dialect.type_descriptor(String())
