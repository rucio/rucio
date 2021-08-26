# -*- coding: utf-8 -*-
# Copyright 2015-2021 CERN
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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2015-2017
# - Martin Barisits <martin.barisits@cern.ch>, 2016-2021
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2021

import os
import sys

from setuptools import setup


if sys.version_info < (3, 6):
    print('ERROR: Rucio WebUI requires at least Python 3.6 to run.')
    sys.exit(1)

try:
    from setuputil import get_rucio_version
except ImportError:
    sys.path.append(os.path.abspath(os.path.dirname(__file__)))
    from setuputil import get_rucio_version

name = 'rucio-webui'
packages = ['rucio', 'rucio.web', 'rucio.web.ui', 'rucio.web.ui.flask', 'rucio.web.ui.flask.common']
data_files = []
description = "Rucio WebUI Package"

setup(
    name=name,
    version=get_rucio_version(),
    packages=packages,
    package_dir={'': 'lib'},
    data_files=None,
    include_package_data=True,
    scripts=None,
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
    install_requires=['rucio>=1.2.5', ],
)
