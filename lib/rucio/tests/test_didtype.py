# -*- coding: utf-8 -*-
# Copyright CERN since 2019
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

from rucio.common.didtype import DID
from rucio.common.exception import DIDError


class TestDIDType:
    ''' Test the DIDType class '''

    def _test_did(self, did, cmp_str, diff_half_did=DID(scope='diff'), diff_full_did=DID('sdiff:ndiff'), is_valid=True):
        stat = 0
        did_as_str = str(did)
        if did == diff_half_did:
            stat = 1
        if did == diff_full_did:
            stat += 2
        if did != cmp_str:
            stat += 4
        if did_as_str != cmp_str:
            stat += 8
        if did_as_str != did:
            stat += 16
        if did.is_valid_format() != is_valid:
            stat += 32

        if stat != 0:
            self.success = False
        return (stat, cmp_str)

    def _print_test(self, result):
        if result[0] != 0:
            print('Test failed {}: {}'.format(result[0], result[1]))

    def test_did_type(self):
        ''' Test DIDType '''
        self.success = True
        try:
            self._print_test(self._test_did(DID(), ''))
            self._print_test(self._test_did(DID('scope:name.did.str'), 'scope:name.did.str'))
            self._print_test(self._test_did(DID('user.implicit.scope.in.name'), 'user.implicit:user.implicit.scope.in.name'))
            self._print_test(self._test_did(DID('custom.scope', 'custom.name'), 'custom.scope:custom.name'))
            self._print_test(self._test_did(DID(['list.scope', 'list.name']), 'list.scope:list.name'))
            self._print_test(self._test_did(DID(('tuple.scope', 'tuple.name')), 'tuple.scope:tuple.name'))
            self._print_test(self._test_did(DID({'scope': 'dict.scope', 'name': 'dict.name'}), 'dict.scope:dict.name'))
            self._print_test(self._test_did(DID(scope='kw.scope'), 'kw.scope'))
            self._print_test(self._test_did(DID(name='kw.name'), 'kw.name'))
            self._print_test(self._test_did(DID(name='user.kw.implicit.scope'), 'user.kw:user.kw.implicit.scope'))
            self._print_test(self._test_did(DID(scope='kw.scope', name='kw.name'), 'kw.scope:kw.name'))
            self._print_test(self._test_did(DID(did={'scope': 'kw.did.scope', 'name': 'kw.did.name'}), 'kw.did.scope:kw.did.name'))
            self._print_test(self._test_did(DID(did=['kw.list.scope', 'kw.list.name']), 'kw.list.scope:kw.list.name'))
            self._print_test(self._test_did(DID(did=('kw.tuple.scope', 'kw.tuple.name')), 'kw.tuple.scope:kw.tuple.name'))
            self._print_test(self._test_did(DID('arg.scope', name='kwarg.name'), 'arg.scope:kwarg.name'))
            self._print_test(self._test_did(DID('arg.name', scope='kwarg.scope'), 'kwarg.scope:arg.name'))
            x = DID('scope.copy:name.test')
            y = DID(x)
            if x != y:
                print('Copy failed: {} != {}'.format(x, y))
                self.success = False
        except DIDError as err:
            print('Exception: {}'.format(err))
            self.success = False

        try:
            DID('non.implicit.single.string')
            print('Exception for invalid DID did not work!')
            self.success = False
        except DIDError:
            pass

        try:
            DID('invalid', 'user.implicit:user:invalid')
            print('Exception for invalid DID did not work!')
            self.success = False
        except DIDError:
            pass

        try:
            DID('user.implicit:user:invalid')
            print('Exception for invalid DID did not work!')
            self.success = False
        except DIDError:
            pass

        assert self.success
