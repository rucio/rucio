# -*- coding: utf-8 -*-
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
import typing

import pytest

from rucio.web.rest.flaskapi.v1.common import try_stream


def _try_stream_to_bytes(application, response_bytes: typing.List[bytes], generator: typing.Iterator[typing.AnyStr]):
    response = try_stream(generator)
    response = application.process_response(response)
    assert response.content_type == 'application/x-json-stream'
    assert response.is_streamed

    for part in response.iter_encoded():
        print(repr(part))
        assert isinstance(part, bytes)
        response_bytes.append(part)


def _cut_at_newlines(bytes_list: typing.List[bytes]) -> typing.List[bytes]:
    byte_string = b''
    for part in bytes_list:
        byte_string += part
    return byte_string.split(b'\n')


def test_try_stream_error_after_one_item(flask_application):
    test_object = {'some': 'object'}

    def generate_with_error():
        yield json.dumps(test_object) + '\n'
        raise RuntimeError('Error for testing')

    with flask_application.app_context():
        with flask_application.test_request_context('/test_try_stream_error_after_one_item'):
            response_bytes: typing.List[bytes] = []
            with pytest.raises(RuntimeError, match='Error for testing'):
                _try_stream_to_bytes(flask_application, response_bytes, generate_with_error())
            response_docs = _cut_at_newlines(response_bytes)
            assert len(response_docs) == 1

            with pytest.raises(json.JSONDecodeError):
                print("Cropped JSON response:", repr(response_docs[0]))
                json.loads(response_docs[0])


def test_try_stream_one_item_no_error(flask_application):
    test_object = {'some': 'object'}

    def generate_without_error():
        yield json.dumps(test_object) + '\n'

    with flask_application.app_context():
        with flask_application.test_request_context('/test_try_stream_one_item_no_error'):
            response_bytes: typing.List[bytes] = []
            _try_stream_to_bytes(flask_application, response_bytes, generate_without_error())
            response_docs = _cut_at_newlines(response_bytes)
            assert len(response_docs) == 2

            response_object = json.loads(response_docs[0])
            assert response_object == test_object
            assert response_docs[1] == b''


def test_try_stream_error_after_two_items(flask_application):
    first_object = {'some': 'object'}
    second_object = {'another': 'object'}

    def generate_with_error():
        yield json.dumps(first_object) + '\n'
        yield json.dumps(second_object) + '\n'
        raise RuntimeError('Error for testing')

    with flask_application.app_context():
        with flask_application.test_request_context('/test_try_stream_error_after_two_items'):
            response_bytes: typing.List[bytes] = []
            with pytest.raises(RuntimeError, match='Error for testing'):
                _try_stream_to_bytes(flask_application, response_bytes, generate_with_error())
            response_docs = _cut_at_newlines(response_bytes)
            assert len(response_docs) == 2

            first_object_response = json.loads(response_docs[0])
            assert first_object_response == first_object
            with pytest.raises(json.JSONDecodeError):
                print("Cropped JSON response from second object:", repr(response_docs[1]))
                json.loads(response_docs[1])


def test_try_stream_two_items_no_error(flask_application):
    first_object = {'some': 'object'}
    second_object = {'another': 'object'}

    def generate_without_error():
        yield json.dumps(first_object) + '\n'
        yield json.dumps(second_object) + '\n'

    with flask_application.app_context():
        with flask_application.test_request_context('/test_try_stream_two_items_no_error'):
            response_bytes: typing.List[bytes] = []
            _try_stream_to_bytes(flask_application, response_bytes, generate_without_error())
            response_docs = _cut_at_newlines(response_bytes)
            assert len(response_docs) == 3

            first_object_response = json.loads(response_docs[0])
            assert first_object_response == first_object
            second_object_response = json.loads(response_docs[1])
            assert second_object_response == second_object
            assert response_docs[2] == b''


def test_try_stream_empty(flask_application):
    def empty_generator():
        yield from list()

    with flask_application.app_context():
        with flask_application.test_request_context('/test_try_stream_empty'):
            response = try_stream(empty_generator())
            response = flask_application.process_response(response)
            assert response.content_type == 'application/x-json-stream'
            assert not response.is_streamed
            assert response.data == b''
