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
import os
import hashlib
from unittest.mock import Mock, patch
from inspect import signature, Parameter

from rucio.tests.common import skip_rse_tests_with_accounts
from rucio.tests.temp_factories import TemporaryFileFactory
from rucio.common.utils import execute
from rucio.common import exception
from rucio.rse import rsemanager
from rucio.rse.protocols.webdav import Default as Protocol


@skip_rse_tests_with_accounts
class TestRseWEBDAV:
    def setup_method(self):
        """
        WEBDAV (RSE/PROTOCOLS):
        Setting up a new protocol and connection for each test.
        """
        info = rsemanager.get_rse_info('WEB1')
        self.protocol: Protocol = rsemanager.create_protocol(info, 'write')
        self.protocol.connect()

    def test_head(self):
        """
        WEBDAV (RSE/PROTOCOLS):
        Test a HEAD on the webdav server. Very basic.
        """
        self.protocol.session.request(
            "HEAD", "https://web1/rucio",
            verify=False, timeout=self.protocol.timeout, cert=self.protocol.cert
        )

    def test_exists(self, file_factory: TemporaryFileFactory):
        """
        WEBDAV (RSE/PROTOCOLS)
        check if a file exists using the webdav protocol.
        """

        tmpfile = file_factory.file_generator()
        status, out, err = execute(
            f"curl -T {tmpfile} -k https://web1/rucio/{tmpfile.name}"
        )
        assert f"Resource /rucio/{tmpfile.name} has been created." in out

        assert self.protocol.exists(self.protocol.path2pfn(tmpfile.name))

    def test_get(self, file_factory: TemporaryFileFactory):
        """
        WEBDAV (RSE/PROTOCOLS)
        get a file stored in the RSE using webdav. compare it to
        """

        tmppath = file_factory.file_generator()
        dwnpath = 'downloaded.data'
        status, out, err = execute(
            f"curl -T {tmppath} -k https://web1/rucio/{tmppath.name}"
        )
        assert f"Resource /rucio/{tmppath.name} has been created." in out

        self.protocol.get(tmppath.name, dwnpath)

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
        self.protocol.put(tmpfile, tmpfile.name)
        assert self.protocol.exists(tmpfile.name)

        # raise 409 FilreReplicaAlreadyExists issue: response is 204??
        # TODO: handle put file to existing filename

    def test_rename(self, file_factory: TemporaryFileFactory):
        """
        WEBDAV (RSE/PROTOCOLS)
        rename a remote file using webdav.
        """
        # upload file A
        tmpfile = file_factory.file_generator()
        status, out, err = execute(
            f"curl -T {tmpfile} -k https://web1/rucio/A"
        )
        assert "Resource /rucio/A has been created." in out

        # assert file A is present and B not -> use exists for this
        assert self.protocol.exists(self.protocol.path2pfn("A"))
        assert not self.protocol.exists(self.protocol.path2pfn("B"))

        # rename file A to file B
        self.protocol.rename(
            self.protocol.path2pfn("A"), self.protocol.path2pfn("B")
        )

        # assert file B is present and A not
        assert not self.protocol.exists(self.protocol.path2pfn("A"))
        assert self.protocol.exists(self.protocol.path2pfn("B"))
        # TODO ?? compare local to remote

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
        self.protocol.delete(tmpfile.name)
        assert not self.protocol.exists(self.protocol.path2pfn(tmpfile.name))

    def test_mkdir(self):
        """
        WEBDAV (RSE/PROTOCOLS)
        create a directory (collection) remotely using webdav.
        """
        # create directory and test
        self.protocol.mkdir("mkdir")

        status, out, err = execute("curl -k https://web1/rucio/")
        assert '<a href="mkdir/"> mkdir/</a>' in out
        status, out, err = execute("curl -k https://web1/rucio/mkdir/")
        assert '<a href="/rucio/"> Parent Directory</a>' in out

        # create directory again -- assert issue
        # mkdir does not distinguish 201 and 405 (already created) so go lower
        result = self.protocol.session.request(
            "MKCOL", "https://web1:443/rucio/mkdir",
            verify=False, timeout=self.protocol.timeout, cert=self.protocol.cert
        )
        assert result.status_code == 405

    def test_ls(self, file_factory: TemporaryFileFactory):
        """
        WEBDAV (RSE/PROTOCOLS)
        test listing of entries in a remote directory (collection) using webdav.
        """
        # create folder
        lsfolder = "https://web1/rucio/ls"
        status, out, err = execute(f"curl -k -X 'MKCOL' {lsfolder}")
        assert "201 Created" in out

        # create and upload multiple
        localfiles = [file_factory.file_generator() for i in range(5)]
        for tmpfile in localfiles:
            status, out, err = execute(
                f"curl -T {tmpfile} -k https://web1/rucio/ls/{tmpfile.name}"
            )
            assert f"Resource /rucio/ls/{tmpfile.name} has been created." in out

        # execute ls command
        # TODO: read in RRC if the remote list will include the base directory
        # right now i will just act as if
        remotelist: list[str] = self.protocol.ls('ls')
        remotelist = [f.split("/")[-1] for f in remotelist]  # only name
        remotelist = list(filter(lambda x: x != "", remotelist))

        # check if all files are present (set equality)
        assert set(remotelist) == set([f.name for f in localfiles])

        # clean up remote
        status, out, err = execute(f"curl -k -X 'DELETE' {lsfolder}")
        # TODO find some assert to put here

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

    @pytest.mark.xfail
    def test_get_space_usage(self):
        """
        WEBDAV (RSE/PROTOCOLS)
        RSE space usage information using webdav.
        """
        totalsize, unusedsize = self.protocol.get_space_usage()
        unusedsize = int(unusedsize)

    @pytest.mark.parametrize("sidefx_name", ["ConnectionError", "ReadTimeout"])
    @pytest.mark.parametrize(
        "runfunc_name", ["stat", "ls", "mkdir", "delete", "rename", "get"]
    )
    def test_handle_timeout(self, runfunc_name: str, sidefx_name: str):
        """
        WEBDAV (RSE/PROTOCOLS)
        Test if a requests ReadTimeout raises rucio ServiceUnavailable

        'exists' and 'get_space_usage' are not included because they have no
        specific handling of this error
        """
        import requests.exceptions
        side_effect = getattr(requests.exceptions, sidefx_name)
        self.protocol.session.request = Mock(side_effect=side_effect)
        runfunc = getattr(self.protocol, runfunc_name)
        num_of_args = len(list(
            filter(
                lambda param: param.default is Parameter.empty,
                signature(runfunc).parameters.values()
            )
        ))

        if runfunc_name == "ls":
            self.protocol.exists = Mock()

        with pytest.raises(exception.ServiceUnavailable):
            runfunc(*[Mock() for i in range(num_of_args)])

    @pytest.mark.parametrize("sidefx_name", ["ConnectionError", "ReadTimeout"])
    def test_put_error_handling(self, sidefx_name: str):
        """
        WEBDAV (RSE/PROTOCOLS)
        Test if a requests ReadTimeout or ConnectionError raises rucio
        ServiceUnavailable for put (because put needs to be handled differently)
        """
        import requests.exceptions
        side_effect = getattr(requests.exceptions, sidefx_name)
        self.protocol.session.put = Mock(side_effect=side_effect)

        patch_os_path_exists = patch("os.path.exists")
        patch_uploadchunks = patch("rucio.rse.protocols.webdav.UploadInChunks")

        patch_os_path_exists.start()
        patch_uploadchunks.start()

        with pytest.raises(exception.ServiceUnavailable):
            self.protocol.put(Mock(), Mock())

        patch.stopall()
