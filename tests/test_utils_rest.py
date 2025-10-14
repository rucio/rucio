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
import logging

import pytest
from werkzeug import exceptions

from rucio.web.rest.flaskapi.v1.common import param_get_bool


@pytest.mark.parametrize(
    'params,kwargs,raise_log,raise_error',
    [
        ({"object": False}, {}, False, False),
        ({"object": True}, {}, False, False),
        ({"object": "true"}, {}, False, False),
        ({"object": "false"}, {}, False, False),
        ({"object": '0'}, {}, True, False),
        ({"object": '1'}, {}, True, False),
        ({"object": 1}, {}, True, False),
        ({"object": 0}, {}, True, False),
        ({"object": 'Incorrect Type'}, {}, False, True),
        ({}, {}, False, True),
        ({}, {"default": True}, False, False),
        ({"object": None}, {"default": False}, False, True),
        ({}, {"default": "Incorrect Type"}, False, True),
        ({"object": "trUE"}, {}, False, False),
        ({"object": "FALSE"}, {}, False, False),
    ],
    ids=[
        "Basic Bool - False",
        "Basic bool - True",
        "String Bool - True",
        "String Bool - False",
        "Int-like str bool - False",
        "Int-like str bool - True",
        "Int bool - False",
        "Int bool - True",
        "Type Error",
        "No object, no default",
        "No object, yes default",
        "None object, yes default",
        "No object, invalid default type",
        "Str bool, variant case - True",
        "Str bool, variant case - False"
    ]
)
def test_param_get_bool(params, kwargs, raise_log, raise_error, caplog):
    with caplog.at_level(logging.WARNING):
        if raise_error:
            with pytest.raises(exceptions.HTTPException):
                param_get_bool(params, "object", **kwargs)

        else:
            out = param_get_bool(params, "object", **kwargs)
            assert isinstance(out, bool)

    if raise_log:
        assert "Booleans should only accept true/false. Please change 0/1 to true/false." in caplog.text
