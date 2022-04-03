# -*- coding: utf-8 -*-
# Copyright 2012-2020 CERN
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
#
# Authors:
# - Vincent Garonne <vgaronne@gmail.com>, 2012-2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012-2018
# - Angelos Molfetas <Angelos.Molfetas@cern.ch>, 2012
# - Thomas Beermann <thomas.beermann@cern.ch>, 2012
# - Joaquin Bogado <jbogado@linti.unlp.edu.ar>, 2014-2018
# - Cheng-Hsi Chao <cheng-hsi.chao@cern.ch>, 2014
# - Cedric Serfon <cedric.serfon@cern.ch>, 2015
# - Martin Barisits <martin.barisits@cern.ch>, 2015-2016
# - Frank Berghaus <frank.berghaus@cern.ch>, 2017-2018
# - Tobias Wegner <twegner@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from rucio.common.utils import execute
import os
from rucio.common import config
from modulefinder import ModuleFinder
import importlib


class TestModuleImport():
    def test_import(self):
        """ """
        cmd = 'rucio --version'
        exitcode, out, err = execute(cmd)
        assert 'ImportError' not in err
        assert 'ImportError' not in out
        assert 'Exception' not in err
        assert 'Exception' not in out

    def test_client_modules(self):
        configdirs = ["/opt/rucio/lib/rucio/client/"]
        if 'RUCIO_HOME' in os.environ:
            configdirs.append('%s/lib/rucio/client/' % os.environ['RUCIO_HOME'])
        if 'VIRTUAL_ENV' in os.environ:
            configdirs.append('%s/lib/rucio/client/' % os.environ['VIRTUAL_ENV'])
        path = (os.path.join(confdir, 'lib') for confdir in configdirs)
        path = next(iter(filter(os.path.exists, path)), None)

        result = module_find(path)
        error = False
        for import_name in result.modules:
            try:
                importlib.import_module(import_name)
            except Exception:
                print("ERROR: unable to import" + import_name)
                error = True
        # if error:
        # raise ImportError

    def test_credentials(self):
        try:
            credentials = config.get_rse_credentials()
        except Exception:
            print("\nWARN: failed to load credentials file\n")
            credentials = None
        try:
            credentials_template = config.get_rse_credentials(None, True)
        except Exception:
            print("\nWARN: failed to load credentials template file\n")
            credentials_template = None
        if credentials and credentials_template and not compare_credentials(credentials, credentials_template):
            print("\nWARN: credentials could be wrong\n")

    def test_config(self):
        try:
            _config = config.get_config()
        except Exception:
            print("\nWARN: failed to load config file")
            _config = None
        try:
            config_template = config.get_config(True)
        except Exception:
            print("\nWARN: failed to load config template file")
            config_template = None
        if _config and config_template and not compare_config(_config, config_template):
            print("\nWARN: config could be wrong\n")


def module_find(files):
    mf = ModuleFinder()
    for fname in files:
        mf.run_script(fname)
    return mf


def get_list_of_python_files(dirName):
    listOfFile = os.listdir(dirName)
    allFiles = list()
    for entry in listOfFile:
        fullPath = os.path.join(dirName, entry)
        if os.path.isdir(fullPath):
            allFiles = allFiles + get_list_of_python_files(fullPath)
        elif fullPath.endswith(".py"):
            allFiles.append(fullPath)
    return allFiles


def compare_credentials(creds, creds_template):
    for key, value in creds_template.items():
        if key not in creds.keys():
            return False
        for _key in value:
            _value = value[_key]
            if _key not in creds[key].keys():
                return False
            _data_template = _value
            _data = creds[key][_key]
            if _data != _data_template:
                return False
    return True


def compare_config(config, config_template):
    if sorted(config.sections()) != sorted(config_template.parser.sections()):
        return False
    for section in config.sections():
        if sorted([i[0] for i in config.items(section)]) != sorted([i[0] for i in config_template.parser.items(section)]):
            return False
    return True

