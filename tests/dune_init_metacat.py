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

from metacat.webapi import MetaCatClient

client = MetaCatClient("http://dev_metacat_1:8080/")
client.login_password("admin", "admin")

# add the containers, datasets and files created by run_tests.sh -ir
# to MetaCat so that the DUNE add_did permission check passes
client.create_namespace("test")

client.create_dataset("test:container")
client.create_dataset("test:dataset1")
client.create_dataset("test:dataset2")
client.create_dataset("test:dataset3")

client.add_child_dataset("test:container", "test:dataset1")
client.add_child_dataset("test:container", "test:dataset2")

client.declare_file(did="test:file1", dataset_did="test:dataset1")
client.declare_file(did="test:file2", dataset_did="test:dataset1")
client.declare_file(did="test:file3", dataset_did="test:dataset2")
client.declare_file(did="test:file4", dataset_did="test:dataset2")
client.add_files("test:dataset3", file_list=[{"did": "test:file4"}])
