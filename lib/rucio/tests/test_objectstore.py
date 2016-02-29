# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Wen Guan, <wen.guan@cern.ch>, 2016

import commands
from nose.tools import raises

from rucio.client.objectstoreclient import ObjectStoreClient
from rucio.common import objectstore
from rucio.common import exception


class TestObjectStoreCommon:

    def setup(self):
        self.url = 's3+https://cephgw.usatlas.bnl.gov:8443/rucio_bucket/test_public'
        self.rse = 'BNL-OSG2_ES'
        ret = objectstore.get_signed_urls([self.url], rse=self.rse, operation='write')
        if isinstance(ret[self.url], Exception):
            raise ret[self.url]
        command = 'curl --request PUT --upload-file /bin/hostname "%s"' % str(ret[self.url])
        status, output = commands.getstatusoutput(command)
        if status:
            raise Exception(output)
        if 'AccessDenied' in output:
            raise Exception(output)

    def test_connect(self):
        """ OBJECTSTORE (COMMON): Connect """
        objectstore.connect(self.rse, self.url)

    def test_get_signed_urls_read(self):
        """ OBJECTSTORE (COMMON): Get signed urls for read """
        ret = objectstore.get_signed_urls([self.url], rse=self.rse, operation='read')
        if isinstance(ret[self.url], Exception):
            raise ret[self.url]

        # read
        command = 'curl "%s" > /dev/null' % ret[self.url]
        status, output = commands.getstatusoutput(command)
        if status:
            raise Exception(output)

        # write
        command = 'curl --request PUT --upload-file /bin/hostname "%s"' % str(ret[self.url])
        status, output = commands.getstatusoutput(command)
        if status:
            raise Exception(output)
        if 'AccessDenied' not in output:
            raise Exception(output)

    def test_get_signed_urls_write(self):
        """ OBJECTSTORE (COMMON): Get signed urls for write """
        ret = objectstore.get_signed_urls([self.url], rse=self.rse, operation='write')
        if isinstance(ret[self.url], Exception):
            raise ret[self.url]

        # write
        command = 'curl --request PUT --upload-file /bin/hostname "%s"' % str(ret[self.url])
        status, output = commands.getstatusoutput(command)
        if status:
            raise Exception(output)
        if 'AccessDenied' in output:
            raise Exception(output)

        # read
        command = 'curl "%s" > /dev/null' % ret[self.url]
        status, output = commands.getstatusoutput(command)
        if status:
            raise Exception(output)

    @raises(exception.SourceNotFound)
    def test_get_signed_urls_read_not_exists(self):
        """ OBJECTSTORE (COMMON): Get signed not exist urls for read """
        url = '%s_not_exist' % (self.url)
        ret = objectstore.get_signed_urls([url], rse=self.rse, operation='read')
        if isinstance(ret[url], Exception):
            raise ret[url]
        raise Exception("Respone not as expected: should catch SourceNotFound")

    def test_get_metadata(self):
        """ OBJECTSTORE (COMMON): Get metadata """
        url = self.url
        ret = objectstore.get_metadata([url], rse=self.rse)
        if isinstance(ret[url], Exception):
            raise ret[url]
        if 'filesize' not in ret[url]:
            raise Exception("Respone not as expected: should return {'filesize': filesize}, but it returns: %s" % ret[url])

    def test_rename(self):
        """ OBJECTSTORE (COMMON): Rename """
        url = self.url
        new_url = '%s_new' % url
        objectstore.rename(url, new_url, rse=self.rse)
        ret = objectstore.get_metadata([url], rse=self.rse)
        if not isinstance(ret[url], exception.SourceNotFound):
            raise ret[url]
        ret = objectstore.get_metadata([new_url], rse=self.rse)
        if isinstance(ret[new_url], Exception):
            raise ret[new_url]
        if 'filesize' not in ret[new_url]:
            raise Exception("Respone not as expected: should return {'filesize': filesize}, but it returns: %s" % ret[url])

    @raises(exception.SourceNotFound)
    def test_get_metadata_not_exist(self):
        """ OBJECTSTORE (COMMON): Get metadata for not exist url """
        url = '%s_not_exist' % (self.url)
        ret = objectstore.get_metadata([url], rse=self.rse)
        if isinstance(ret[url], Exception):
            raise ret[url]
        raise Exception("Respone not as expected: should catch SourceNotFound")

    def test_delete(self):
        """ OBJECTSTORE (COMMON): Delete urls """
        urls = []
        for i in range(10):
            url = '%s_%s' % (self.url, i)
            urls.append(url)
        ret = objectstore.get_signed_urls(urls, rse=self.rse, operation='write')
        for url in urls:
            if isinstance(url, Exception):
                raise ret[self.url]

            # write
            command = 'curl --request PUT --upload-file /bin/hostname "%s"' % ret[url]
            status, output = commands.getstatusoutput(command)
            if status:
                raise Exception(output)
            if 'AccessDenied' in output:
                raise Exception(output)

        ret = objectstore.delete(urls, rse=self.rse)
        for url in urls:
            if isinstance(ret[url], Exception):
                raise ret[url]

    def test_delete_dir(self):
        """ OBJECTSTORE (COMMON): Delete dir """
        urls = []
        for i in range(10):
            url = '%s_%s' % (self.url, i)
            urls.append(url)
        ret = objectstore.get_signed_urls(urls, rse=self.rse, operation='write')
        for url in urls:
            if isinstance(url, Exception):
                raise ret[self.url]

            # write
            command = 'curl --request PUT --upload-file /bin/hostname "%s"' % ret[url]
            status, output = commands.getstatusoutput(command)
            if status:
                raise Exception(output)
            if 'AccessDenied' in output:
                raise Exception(output)

        status, output = objectstore.delete_dir(self.url, rse=self.rse)
        if status:
            raise Exception(output)


class TestObjectStoreClients:

    def setup(self):
        self.os_client = ObjectStoreClient()
        self.url = 's3+https://cephgw.usatlas.bnl.gov:8443/rucio_bucket/test_public'
        self.rse = 'BNL-OSG2_ES'
        ret = objectstore.get_signed_urls([self.url], rse=self.rse, operation='write')
        if isinstance(ret[self.url], Exception):
            raise ret[self.url]
        command = 'curl --request PUT --upload-file /bin/hostname "%s"' % ret[self.url]
        status, output = commands.getstatusoutput(command)
        if status:
            raise Exception(output)
        if 'AccessDenied' in output:
            raise Exception(output)

    def test_connect(self):
        """ OBJECTSTORE (CLIENT): Connect """
        self.os_client.connect(self.rse, self.url)

    def test_get_signed_url_read(self):
        """ OBJECTSTORE (CLIENT): Get signed url for read """
        ret = self.os_client.get_signed_url(self.url, rse=self.rse, operation='read')
        if type(ret) not in [str, unicode]:
            raise Exception("Return %s is not as expected.")

        # read
        command = 'curl "%s" > /dev/null' % str(ret)
        status, output = commands.getstatusoutput(command)
        if status:
            raise Exception(output)

        # write
        command = 'curl --request PUT --upload-file /bin/hostname "%s"' % ret
        status, output = commands.getstatusoutput(command)
        if status:
            raise Exception(output)
        if 'AccessDenied' not in output:
            raise Exception(output)

    def test_get_signed_url_write(self):
        """ OBJECTSTORE (CLIENT): Get signed url for write """
        ret = self.os_client.get_signed_url(self.url, rse=self.rse, operation='write')
        if type(ret) not in [str, unicode]:
            raise Exception("Return %s is not as expected.")

        # write
        command = 'curl --request PUT --upload-file /bin/hostname "%s"' % ret
        status, output = commands.getstatusoutput(command)
        if status:
            raise Exception(output)
        if 'AccessDenied' in output:
            raise Exception(output)

        # read
        command = 'curl "%s" > /dev/null' % ret
        status, output = commands.getstatusoutput(command)
        if status:
            raise Exception(output)

    @raises(exception.SourceNotFound)
    def test_get_signed_url_read_not_exists(self):
        """ OBJECTSTORE (CLIENT): Get signed not exist url for read """
        url = '%s_not_exist' % (self.url)
        self.os_client.get_signed_url(url, rse=self.rse, operation='read')
        raise Exception("Respone not as expected: should catch SourceNotFound")

    def test_get_signed_urls_read(self):
        """ OBJECTSTORE (CLIENT): Get signed urls for read """
        ret = self.os_client.get_signed_urls([self.url], rse=self.rse, operation='read')
        if isinstance(ret[self.url], Exception):
            raise ret[self.url]

        # read
        command = 'curl "%s" > /dev/null' % ret[self.url]
        status, output = commands.getstatusoutput(command)
        if status:
            raise Exception(output)

        # write
        command = 'curl --request PUT --upload-file /bin/hostname "%s"' % ret[self.url]
        status, output = commands.getstatusoutput(command)
        if status:
            raise Exception(output)
        if 'AccessDenied' not in output:
            raise Exception(output)

    def test_get_signed_urls_write(self):
        """ OBJECTSTORE (CLIENT): Get signed urls for write """
        ret = self.os_client.get_signed_urls([self.url], rse=self.rse, operation='write')
        if isinstance(ret[self.url], Exception):
            raise ret[self.url]

        # write
        command = 'curl --request PUT --upload-file /bin/hostname "%s"' % ret[self.url]
        status, output = commands.getstatusoutput(command)
        if status:
            raise Exception(output)
        if 'AccessDenied' in output:
            raise Exception(output)

        # read
        command = 'curl "%s" > /dev/null' % ret[self.url]
        status, output = commands.getstatusoutput(command)
        if status:
            raise Exception(output)

    @raises(exception.SourceNotFound)
    def test_get_signed_urls_read_not_exists(self):
        """ OBJECTSTORE (CLIENT): Get signed not exist urls for read """
        url = '%s_not_exist' % (self.url)
        self.os_client.get_signed_urls([url], rse=self.rse, operation='read')
        raise Exception("Respone not as expected: should catch SourceNotFound")

    def test_get_metadata(self):
        """ OBJECTSTORE (CLIENT): Get metadata """
        url = self.url
        ret = self.os_client.get_metadata([url], rse=self.rse)
        if isinstance(ret[url], Exception):
            raise ret[url]
        if 'filesize' not in ret[url]:
            raise Exception("Respone not as expected: should return {'filesize': filesize}, but it returns: %s" % ret[url])

    @raises(exception.SourceNotFound)
    def test_get_metadata_not_exist(self):
        """ OBJECTSTORE (CLIENT): Get metadata for not exist url """
        url = '%s_not_exist' % (self.url)
        self.os_client.get_metadata([url], rse=self.rse)
        raise Exception("Respone not as expected: should catch SourceNotFound")

    def test_rename(self):
        """ OBJECTSTORE (CLIENT): Rename """
        url = self.url
        new_url = '%s_new' % url
        self.os_client.rename(url, new_url, rse=self.rse)
        try:
            self.os_client.get_metadata([url], rse=self.rse)
        except exception.SourceNotFound:
            pass

        ret = self.os_client.get_metadata([new_url], rse=self.rse)
        if isinstance(ret[new_url], Exception):
            raise ret[new_url]
        if 'filesize' not in ret[new_url]:
            raise Exception("Respone not as expected: should return {'filesize': filesize}, but it returns: %s" % ret[new_url])
