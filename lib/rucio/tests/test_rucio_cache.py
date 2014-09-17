# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Wen Guan, <wen.guan@cern.ch>, 2014


import logging
import random

from nose.tools import assert_equal

from rucio.api import rse, did
from rucio.core import replica
from rucio.common import exception
from rucio.daemons.cache.consumer import DID_NOT_FOUND, META_MISMATCH
from rucio.daemons.cache.consumer import cache_add_replicas, cache_delete_replicas, RSE_Volatile


class TestRucioCacheFunc():

    def setup(self):
        """RucioCache (Func): Find necessary rse and dids """
        self.id = int(random.random() * 10000)
        self.rse_exist_volatile = 'RUCIO_CACHE_VOLATILE' + str(self.id)
        try:
            rse.add_rse(self.rse_exist_volatile, 'root', deterministic=True, volatile=True)
        except exception.Duplicate:
            logging.warning("rse RUCIO_CACHE_VOLATILE already there")

        self.rse_exist_novolatile = 'RUCIO_CACHE_NOVOLATILE' + str(self.id)
        try:
            rse.add_rse(self.rse_exist_novolatile, 'root', deterministic=True, volatile=False)
        except exception.Duplicate:
            logging.warning("rse RUCIO_CACHE_NOVOLATILE already there")

        self.rse_noExist = 'RUCIO_CACHE_NOEXIST' + str(self.id)
        dids = did.list_dids(scope='mock', filters={}, type='file')
        i = 0
        self.files_exist = []
        self.files_exist_wrong_meta = []
        self.file_replica_on_novolatile = []
        for _did in dids:
            if i < 2:
                i += 1
                meta = did.get_metadata(scope='mock', name=_did[0])
                self.files_exist.append({'scope': meta['scope'], 'name': meta['name'], 'bytes': meta['bytes'], "adler32": meta["adler32"]})
                self.files_exist_wrong_meta.append({'scope': meta['scope'], 'name': meta['name'], 'bytes': 12345678, "adler32": '12345678'})
            elif i < 3:
                meta = did.get_metadata(scope='mock', name=_did[0])
                file = {'scope': meta['scope'], 'name': meta['name'], 'bytes': meta['bytes'], "adler32": meta["adler32"]}
                self.file_replica_on_novolatile.append(file)
                replica.add_replicas(self.rse_exist_novolatile, [file], account='root')

        logging.debug("File Exists: %s " % self.files_exist)
        logging.debug("File Exists with wrong metadata: %s " % self.files_exist_wrong_meta)
        logging.debug("File Exists on volatie rses: " % self.file_replica_on_novolatile)

        self.files_noExist = [{'scope': 'mock', 'name': 'file_notexist', "bytes": 1, "adler32": "0cc737eb"}]
        logging.debug("File not Exists: %s " % self.files_noExist)
        self.account = 'root'
        self.lifetime = 2

    def teardown(self):
        """RucioCache (Func): Clean necessary rse and dids """
        try:
            replica.delete_replicas(self.rse_exist_novolatile, self.file_replica_on_novolatile)
            rse.del_rse(self.rse_exist_volatile, 'root')
            rse.del_rse(self.rse_exist_novolatile, 'root')
        except Exception, e:
            print e

    def test_cache_add_delete_replicas(self):
        """ RucioCache(Func): Test rucio cache add and delete replicas(success) """
        ret = cache_add_replicas(self.rse_exist_volatile, self.files_exist, self.account, self.lifetime)
        assert_equal(ret, 0)

        for file in self.files_exist:
            reps = replica.get_replica(self.rse_exist_volatile, file['scope'], file['name'])
            assert_equal(len(reps) > 0, True)

        ret = cache_delete_replicas(self.rse_exist_volatile, self.files_exist, self.account)
        assert_equal(ret, 0)

        for file in self.files_exist:
            try:
                reps = replica.get_replica(self.rse_exist_volatile, file['scope'], file['name'])
                assert False
            except Exception, e:
                if "No row was found" in str(e):
                    assert True
                else:
                    assert False

    def test_cache_add_replicas_no_rse(self):
        """ RucioCache(Func): Test rucio cache add replicas to not existed rse(failed) """
        try:
            cache_add_replicas(self.rse_noExist, self.files_exist, self.account, self.lifetime)
            assert False
        except exception.RSENotFound:
            assert True

    def test_cache_delete_replicas_no_rse(self):
        """ RucioCache(Func): Test rucio cache delete replicas on not existed rse(failed) """
        try:
            cache_add_replicas(self.rse_noExist, self.files_exist, self.account, self.lifetime)
            assert False
        except exception.RSENotFound:
            assert True

    def test_cache_add_replicas_file_meta_wrong(self):
        """ RucioCache(Func): Test rucio cache add replica with wrong meta data(failed) """
        ret = cache_add_replicas(self.rse_exist_volatile, self.files_exist_wrong_meta, self.account, self.lifetime)
        assert_equal(ret, META_MISMATCH)

        for file in self.files_exist_wrong_meta:
            try:
                replica.get_replica(self.rse_exist_volatile, file['scope'], file['name'])
                assert False
            except Exception, e:
                if "No row was found" in str(e):
                    assert True
                else:
                    assert False

    def test_cache_add_replicas_file_not_exist(self):
        """ RucioCache(Func): Test rucio cache add replica with not existed file(failed) """
        ret = cache_add_replicas(self.rse_exist_volatile, self.files_noExist, self.account, self.lifetime)
        assert_equal(ret, DID_NOT_FOUND)

        for file in self.files_noExist:
            try:
                replica.get_replica(self.rse_exist_volatile, file['scope'], file['name'])
                assert False
            except Exception, e:
                if "No row was found" in str(e):
                    assert True
                else:
                    assert False

    def test_rse_volatie_class(self):
        """ RucioCache(Func): Test rucio cache RSE_Volatile class(success) """
        rse_volatile = RSE_Volatile()
        ret = rse_volatile.get_volatile(self.rse_exist_volatile)
        assert_equal(ret, True)

        ret = rse_volatile.get_volatile(self.rse_exist_novolatile)
        assert_equal(ret, False)
