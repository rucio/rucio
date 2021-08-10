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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2014-2018
# - Martin Barisits <martin.barisits@cern.ch>, 2016-2021
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019
# - Dimitrios Christidis <dimitrios.christidis@cern.ch>, 2019
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Matt Snyder <msnyder@bnl.gov>, 2019
# - Ruturaj Gujar <ruturaj.gujar23@gmail.com>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021

import glob
import os
import shutil
import sys

from setuptools import setup, find_packages

if sys.version_info < (3, 6):
    print('ERROR: Rucio Server requires at least Python 3.6 to run.')
    sys.exit(1)

try:
    from setuputil import server_requirements_table, match_define_requirements, get_rucio_version
except ImportError:
    sys.path.append(os.path.abspath(os.path.dirname(__file__)))
    from setuputil import server_requirements_table, match_define_requirements, get_rucio_version

install_requires, extras_require = match_define_requirements(server_requirements_table)

name = 'rucio'
packages = find_packages(where='lib')
description = "Rucio Package"
data_files = [
    ('rucio/', ['requirements.txt']),
    ('rucio/etc/', glob.glob('etc/*.template')),
    ('rucio/etc/web', glob.glob('etc/web/*.template')),
    ('rucio/tools/', ['tools/bootstrap.py', 'tools/reset_database.py']),
    ('rucio/etc/mail_templates/', glob.glob('etc/mail_templates/*.tmpl')),
]
scripts = glob.glob('bin/rucio*')

if os.path.exists('build/'):
    shutil.rmtree('build/')
if os.path.exists('lib/rucio_clients.egg-info/'):
    shutil.rmtree('lib/rucio_clients.egg-info/')
if os.path.exists('lib/rucio.egg-info/'):
    shutil.rmtree('lib/rucio.egg-info/')

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
    python_requires=">=3.6, <4",
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: Apache Software License',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Operating System :: POSIX :: Linux',
        'Natural Language :: English',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Environment :: No Input/Output (Daemon)', ],
    install_requires=install_requires,
    extras_require=extras_require,
)
