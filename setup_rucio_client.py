# -*- coding: utf-8 -*-
# Copyright 2014-2021 CERN
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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2014-2018
# - Martin Barisits <martin.barisits@cern.ch>, 2017-2020
# - Ruturaj Gujar <ruturaj.gujar23@gmail.com>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2021
# - James Perry <j.perry@epcc.ed.ac.uk>, 2021

from __future__ import print_function

import os
import shutil
import sys

from setuptools import setup

if sys.version_info < (2, 7):
    print('ERROR: Rucio Client requires at least Python 2.7 to run.')
    sys.exit(1)

try:
    from setuputil import clients_requirements_table, get_rucio_version, match_define_requirements
except ImportError:
    sys.path.append(os.path.abspath(os.path.dirname(__file__)))
    from setuputil import clients_requirements_table, get_rucio_version, match_define_requirements

install_requires, extras_require = match_define_requirements(clients_requirements_table)

# Arguments to the setup script to build Basic/Lite distributions
name = 'rucio-clients'
packages = ['rucio', 'rucio.client', 'rucio.common', 'rucio.common.schema',
            'rucio.rse.protocols', 'rucio.rse']
description = "Rucio Client Lite Package"
data_files = [
    ('', ['requirements.txt']),
    ('etc/', ['etc/rse-accounts.cfg.template', 'etc/rucio.cfg.template', 'etc/rucio.cfg.atlas.client.template']),
]
scripts = ['bin/rucio', 'bin/rucio-admin']

if os.path.exists('build/'):
    shutil.rmtree('build/')
if os.path.exists('lib/rucio_clients.egg-info/'):
    shutil.rmtree('lib/rucio_clients.egg-info/')
if os.path.exists('lib/rucio.egg-info/'):
    shutil.rmtree('lib/rucio.egg-info/')

# For using SSO login option, install these RPM packages: libxml2-devel xmlsec1-devel xmlsec1-openssl-devel libtool-ltdl-devel

setup(
    name=name,
    version=get_rucio_version(),
    packages=packages,
    package_dir={'': 'lib'},
    data_files=data_files,
    include_package_data=True,
    scripts=scripts,
    author="Rucio",
    author_email="rucio-dev@cern.ch",
    description=description,
    license="Apache License, Version 2.0",
    url="https://rucio.cern.ch/",
    python_requires=">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, !=3.5.*, <4",
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: Apache Software License',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Operating System :: POSIX :: Linux',
        'Natural Language :: English',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
    install_requires=install_requires,
    extras_require=extras_require,
)
