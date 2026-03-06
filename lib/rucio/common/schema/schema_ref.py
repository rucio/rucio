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

from typing import Any, Optional

from rucio.common.constants import DEFAULT_VO


class SchemaRef:
    """
    Represents a reference from one object in the schema hierarchy to another.
    This can then be resolved to a value in either the policy package or the
    generic schema module.
    Although this is a small class it is in its own module to avoid causing a
    circular import in __init__.py
    """
    def __init__(self, name: str, offset: Optional[int] = None):
        """
        Initialize a new SchemaRef containing the name of the item
        referred to, and an optional integer offset to be added to
        the item.
        """
        self.name = name
        self.offset = offset

    def resolve(self, vo: str = DEFAULT_VO) -> Any:
        """
        Resolves this SchemaRef, returning the actual value of the
        item referred to.
        """
        from rucio.common.schema import get_schema_value

        result = get_schema_value(self.name, vo)
        if self.offset is not None:
            result = result + self.offset
        return result
