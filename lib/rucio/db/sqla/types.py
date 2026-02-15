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

import json
import uuid

import sqlalchemy.types as types
from sqlalchemy.dialects.mysql import BINARY
from sqlalchemy.dialects.oracle import CLOB, RAW
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.sql import operators
from sqlalchemy.types import CHAR, TEXT, String, TypeDecorator

from rucio.common.exception import InvalidType
from rucio.common.types import InternalAccount, InternalScope


class GUID(TypeDecorator):
    """
    Platform-independent GUID type.

    Uses PostgreSQL's UUID type,
    uses Oracle's RAW type,
    uses MySQL's BINARY type,
    otherwise uses CHAR(32), storing as stringified hex values.

    """

    impl = CHAR

    cache_ok = True

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
                return "%.32x" % uuid.UUID(value).int
            else:
                # hexstring
                return "%.32x" % value.int

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == 'oracle':
            return str(value if isinstance(value, uuid.UUID) else uuid.UUID(bytes=value)).replace('-', '').lower()
        elif dialect.name == 'mysql':
            return str(value if isinstance(value, uuid.UUID) else uuid.UUID(bytes=value)).replace('-', '').lower()
        else:
            return str(value if isinstance(value, uuid.UUID) else uuid.UUID(value)).replace('-', '').lower()


class BooleanString(TypeDecorator):
    """
    Encode True/False/String in a VARCHAR type for all databases.
    """

    impl = String

    cache_ok = True

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
        elif isinstance(value, str):
            if value.lower() == 'true':
                return 'true'
            elif value.lower() == 'false':
                return 'false'

        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value

        if value.lower() == 'true':
            return True
        elif value.lower() == 'false':
            return False
        else:
            return value


class JSON(TypeDecorator):
    """
    Platform independent JSON type with automatic (de)serialization only when needed.

    - PostgreSQL -> JSONB (native, pass-through)
    - MySQL      -> JSON  (native, pass-through)
    - Oracle <21 -> CLOB  (serialize as text + IS JSON checks)
    - Oracle 21+ -> JSON  (native, pass-through via compile hook)
    - Others     -> TEXT  (serialize as text)
    """
    impl = types.JSON
    cache_ok = True

    def _oracle_uses_native_json(self, dialect) -> bool:
        version_info = getattr(dialect, 'server_version_info', None)
        try:
            major = int(version_info[0]) if version_info else None
        except Exception:
            major = None
        return bool(major and major >= 21)
        # TODO: After version 21c, SQLAlchemy will start reporting native JSON support.
        #  From that point on, any table whose column is still a legacy CLOB (because it
        #  was created before native JSON existed) will start receiving raw dicts and
        #  trigger ORA-00932 unless you migrate the column to the real JSON type. This
        #  migration ("ALTER TABLE … MODIFY <column> JSON" for every affected table) must
        #  run once Oracle 21c+ is introduced.

    def _dialect_has_native_json(self, dialect) -> bool:
        if dialect.name in ('postgresql', 'mysql'):
            return True
        if dialect.name == 'oracle':
            return self._oracle_uses_native_json(dialect)
        return False

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(JSONB())
        if dialect.name == 'mysql':
            return dialect.type_descriptor(types.JSON())
        if dialect.name == 'oracle':
            # The column type for DDL is decided via the compiler hook below
            # but query-time Python type needs a descriptor:
            return dialect.type_descriptor(CLOB() if not self._oracle_uses_native_json(dialect)
                                           else types.JSON())
        return dialect.type_descriptor(TEXT())

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if self._dialect_has_native_json(dialect):
            # Let the driver handle it
            return value
        # Textual backends
        if isinstance(value, (str, bytes)):
            return value
        return json.dumps(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if self._dialect_has_native_json(dialect):
            # Already a Python object
            return value
        # Textual backends
        if hasattr(value, 'read') and callable(getattr(value, 'read')):
            try:
                value = value.read()
            except Exception:
                value = str(value)
        if isinstance(value, (bytes, bytearray)):
            value = value.decode()
        if isinstance(value, str):
            try:
                return json.loads(value)
            except (TypeError, ValueError):
                return value
        return value


# The compile hook to pick "JSON" vs "CLOB" in Oracle DDL:
@compiles(JSON, 'oracle')
def compile_oracle_json(type_, compiler, **kw):
    # Control DDL: "JSON" on 21c+, else "CLOB"
    version_info = getattr(compiler.dialect, 'server_version_info', None)
    try:
        major = int(version_info[0]) if version_info else None
    except Exception:
        major = None
    return "JSON" if major and major >= 21 else "CLOB"


class InternalAccountString(TypeDecorator):
    """
    Encode InternalAccount in a VARCHAR type for all databases.
    """

    impl = String

    cache_ok = True

    def load_dialect_imp(self, dialect):
        return dialect.type_descriptor(String(255))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value

        if isinstance(value, str):
            raise InvalidType('Cannot insert to db. Expected InternalAccount, got string type.')
        else:
            return value.internal

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        return InternalAccount(value, from_external=False)

    def coerce_compared_value(self, op, value):
        if op in (operators.like_op, operators.notlike_op):
            return String()
        else:
            return self


class InternalScopeString(TypeDecorator):
    """
    Encode InternalScope in a VARCHAR type for all databases.
    """

    impl = String

    cache_ok = True

    def load_dialect_imp(self, dialect):
        return dialect.type_descriptor(String(255))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value

        if isinstance(value, str):
            raise InvalidType('Cannot insert to db. Expected InternalScope, got string type.')
        else:
            return value.internal

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        return InternalScope(value, from_external=False)

    def coerce_compared_value(self, op, value):
        if op in (operators.like_op, operators.notlike_op):
            return String()
        else:
            return self
