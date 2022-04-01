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
import json
from rucio.common.config import get_config_dirs, get_rse_credentials
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
        files = get_list_of_python_files("C:/Users/lukas/Documents/projects/rucio/lib/rucio/client")
        result = module_find(files)
        error = False
        for import_name in result.modules:
            try:
                importlib.import_module(import_name)
            except Exception:
                print("ERROR: unable to import" + import_name)
                error = True
        if error:
            raise ImportError

    def test_credentials(self):
        try:
            credentials = get_rse_credentials()
        except Exception:
            print("WARN: failed to load credentials file\n")
            credentials = None
        try:
            credentials_template = get_rse_credentials_template()
        except Exception:
            print("WARN: failed to load credentials template file\n")
            credentials_template = None
        if credentials and credentials_template and not compare_credentials(credentials, credentials_template):
            print("WARN: credentials could be wrong\n")

    def test_config(self):
        try:
            config = get_config("rucio.cfg")
        except Exception:
            print("WARN: failed to load config file")
            config = None
        try:
            config_template = get_config("rucio.cfg.template")
        except Exception:
            print("WARN: failed to load config template file")
            config_template = None
        if config and config_template and not compare_config(config, config_template):
            print("WARN: config could be wrong\n")


def module_find(files):
    mf = ModuleFinder()
    for fname in files:
        mf.run_script(fname)
    return mf


def get_list_of_python_files(dirName):
    # create a list of file and sub directories
    # names in the given directory
    listOfFile = os.listdir(dirName)
    allFiles = list()
    # Iterate over all the entries
    for entry in listOfFile:
        # Create full path
        fullPath = os.path.join(dirName, entry)
        # If entry is a directory then get the list of files in this directory
        if os.path.isdir(fullPath):
            allFiles = allFiles + getListOfFiles(fullPath)
        elif fullPath.endswith(".py"):
            allFiles.append(fullPath)
    return allFiles


def get_rse_credentials_template(path_to_credentials_file=None):
    """ Returns credentials for RSEs. """

    path = ''
    if path_to_credentials_file:  # Use specific file for this connect
        path = path_to_credentials_file
    else:  # Use file defined in th RSEMgr
        path = (os.path.join(confdir, 'rse-accounts.cfg.template') for confdir in get_config_dirs())
        path = next(iter(filter(os.path.exists, path)), None)
    try:
        # Load all user credentials
        with open(path) as cred_file:
            credentials = json.load(cred_file)
    except Exception as error:
        raise exception.ErrorLoadingCredentials(error)
    return credentials


def compare_credentials(config, config_template):
    if len(config) == 0:
        return False
    for key, value in config_template.items():
        if key not in config.keys():
            return False
        for _key in value:
            _value = value[_key]
            if _key not in config[key].keys():
                return False
            _data_template = _value
            _data = config[key][_key]
            if _data != _data_template:
                return False
    return True


def compare_config(config, config_template):
    if len(config == 0):
        return False
    for key, values in config_template.items():
        if key not in config.keys():
            return False
        for value in values:
            if value not in config[key]:
                return False
    return True


def get_config(configname):
    path = (os.path.join(confdir, configname) for confdir in get_config_dirs())
    path = next(iter(filter(os.path.exists, path)), None)
    try:
        with open(path) as f:
            section = {}
            current_header = ""
            s = set()
            for line in f:
                if line.startswith("[") and len(s) != 0:
                    section[current_header] = s.copy()
                    current_header = line
                    s.clear()
                if line.startswith("["):
                    current_header = line
                elif current_header != "" and "=" in line:
                    s.add(line.split("=")[0])
            section[current_header] = s
    except OSError:
        print("WARN: unable to open rucio.cfg.template")
    return section
