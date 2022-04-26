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


class TestModuleImport:
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
        path = next(iter(filter(os.path.exists, configdirs)), None)

        if path is None:
            print("ERROR: unable to get path")
            return
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

    def test_load_conf_values(self):
        configdirs = ["/opt/rucio/"]
        if 'RUCIO_HOME' in os.environ:
            configdirs.append('%s/' % os.environ['RUCIO_HOME'])
        if 'VIRTUAL_ENV' in os.environ:
            configdirs.append('%s/' % os.environ['VIRTUAL_ENV'])
        path = next(iter(filter(os.path.exists, configdirs)), None)
        paths = get_list_of_python_files(path)



        for _file in paths:
            import mmap
            try:
                with open(_file, 'rb', 0) as file, \
                        mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as s:
                    if s.find(b'config_get(') != -1:
                        print('\nWARN: configuration could be imported in %s on line\n' % file)
            except Exception:
                pass

def module_find(files):
    mf = ModuleFinder()
    for fname in files:
        mf.run_script(fname)
    return mf


def get_list_of_python_files(dirname):
    list_of_file = os.listdir(dirname)
    all_files = list()
    for entry in list_of_file:
        full_path = os.path.join(dirname, entry)
        if os.path.isdir(full_path):
            all_files = all_files + get_list_of_python_files(full_path)
        elif full_path.endswith(".py"):
            all_files.append(full_path)
    return all_files


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
        if sorted([i[0] for i in config.items(section)]) != sorted(
                [i[0] for i in config_template.parser.items(section)]):
            return False
    return True
