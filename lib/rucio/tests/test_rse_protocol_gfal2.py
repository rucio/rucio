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
import pytest
import hashlib
import os

from rucio.tests.common import skip_rse_tests_with_accounts
from rucio.tests.temp_factories import TemporaryFileFactory
from rucio.common.utils import execute
from rucio.rse import rsemanager
from rucio.rse.protocols.gfal import Default as Protocol


@skip_rse_tests_with_accounts
class TestRseGFAL:
    def setup_method(self):
        """
        GFAL2 (RSE/PROTOCOLS):
        Setting up a new protocol and connection for each test
        """
        info = rsemanager.get_rse_info('WEB1')

        # update rse info
        protocol = info['protocols'][0]
        protocol['impl'] = 'rucio.rse.protocols.gfal.Default'
        protocol['extended_attributes'] = {'web_service_path': '/rucio/'}

        self.protocol: Protocol = rsemanager.create_protocol(info, 'write')
        self.protocol.connect()

    def test_exists(self, file_factory: TemporaryFileFactory):
        """
        GFAL2 (RSE/PROTOCOLS):
        check if a file exists using webdav via gfal protocol.
        """
        tmpfile = file_factory.file_generator()
        status, out, err = execute(
            f"curl -T {tmpfile} -k https://web1/rucio/{tmpfile.name}"
        )
        assert f"Resource /rucio/{tmpfile.name} has been created." in out

        assert self.protocol.exists(self.protocol.path2pfn(tmpfile.name))

    def test_get(self, file_factory: TemporaryFileFactory):
        """
        GFAL2 (RSE/PROTOCOLS)
        get a file stored in the RSE using webdav. compare it to
        """

        tmppath = file_factory.file_generator()
        dwnpath = 'downloaded.data'
        status, out, err = execute(
            f"curl -T {tmppath} -k https://web1/rucio/{tmppath.name}"
        )
        assert f"Resource /rucio/{tmppath.name} has been created." in out

        # Need to use path2pfn here because gfal protocol does not use
        # path2pfn within 'get' (unlike webdav)
        self.protocol.get(self.protocol.path2pfn(tmppath.name), dwnpath)

        # compare file hashes
        with open(tmppath, mode="rb") as f:
            localhash = hashlib.sha256(f.read()).hexdigest()
        with open(dwnpath, mode="rb") as f:
            downhash = hashlib.sha256(f.read()).hexdigest()

        assert localhash == downhash

        os.remove("downloaded.data")

    def test_put(self, file_factory: TemporaryFileFactory):
        """
        WEBDAV (RSE/PROTOCOLS)
        put a local file into the RSE using webdav.
        """
        # create and upload file
        tmpfile = file_factory.file_generator()
        # again, the interface is different for gfal and webdav
        path2pfn = self.protocol.path2pfn(tmpfile.name)
        self.protocol.put(tmpfile.name, path2pfn, tmpfile.parent)
        assert self.protocol.exists(path2pfn)

        # TODO: handle put file to existing filename

    def test_delete(self, file_factory: TemporaryFileFactory):
        """
        WEBDAV (RSE/PROTOCOLS)
        delete a remote file using webdav.
        """
        # upload file
        tmpfile = file_factory.file_generator()
        status, out, err = execute(
            f"curl -T {tmpfile} -k https://web1/rucio/{tmpfile.name}"
        )
        assert f"Resource /rucio/{tmpfile.name} has been created." in out

        # delete file
        self.protocol.delete(self.protocol.path2pfn(tmpfile.name))
        assert not self.protocol.exists(self.protocol.path2pfn(tmpfile.name))

    def test_rename(self, file_factory: TemporaryFileFactory):
        """
        WEBDAV (RSE/PROTOCOLS)
        rename a remote file using webdav.
        """
        # upload file A
        tmpfile = file_factory.file_generator()
        A_name = f"{tmpfile.name}_A"
        B_name = f"{tmpfile.name}_B"
        status, out, err = execute(
            f"curl -T {tmpfile} -k https://web1/rucio/{A_name}"
        )
        assert f"Resource /rucio/{A_name} has been created." in out

        # assert file A is present and B not -> use exists for this
        assert self.protocol.exists(self.protocol.path2pfn(A_name))
        assert not self.protocol.exists(self.protocol.path2pfn(B_name))

        # rename file A to file B
        self.protocol.rename(
            self.protocol.path2pfn(A_name), self.protocol.path2pfn(B_name)
        )

        # assert file B is present and A not
        assert not self.protocol.exists(self.protocol.path2pfn(A_name))
        assert self.protocol.exists(self.protocol.path2pfn(B_name))

    # fail because of gfal checksums, no ADLER32
    @pytest.mark.xfail
    def test_stat(self, file_factory: TemporaryFileFactory):
        """
        WEBDAV (RSE/PROTOCOLS)
        gain stats of a remote file using webdav. At the moment, the only stat
        is the filesize.
        """
        tmppath = file_factory.file_generator()
        status, out, err = execute(
            f"curl -T {tmppath} -k https://web1/rucio/{tmppath.name}"
        )
        assert f"Resource /rucio/{tmppath.name} has been created." in out

        # compare sizes
        localsize = os.stat(tmppath).st_size

        remotestats = self.protocol.stat(self.protocol.path2pfn(tmppath.name))
        assert isinstance(remotestats, dict)
        assert localsize == remotestats["filesize"]

        # add checksum test! but first stat needs to return a checksum too
