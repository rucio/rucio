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

from collections.abc import Sequence
from typing import Literal, Optional, Union

from werkzeug.datastructures import Headers

HeadersType = Union[Headers, dict[str, str], Sequence[tuple[str, str]]]

Response200OK = tuple[Literal[''], Literal[200]]
Response200OKWithHeaders = tuple[Literal[''], Literal[200], Headers]

Response201Created = tuple[Literal['Created'], Literal[201]]

Response206PartialContentWithHeaders = tuple[str, Literal[206], Headers]