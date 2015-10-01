# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013

import uuid

from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.dialects.oracle import RAW
from sqlalchemy.dialects.mysql import BINARY
from sqlalchemy.types import TypeDecorator, CHAR, String


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

        if isinstance(value, bool):
            if value:
                return '1'
            return '0'

        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value

        if value == '1':
            return True
        elif value == '0':
            return False
        else:
            return value
