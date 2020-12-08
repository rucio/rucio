# -*- coding: utf-8 -*-
# Copyright 2015-2020 CERN
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
# - Martin Barisits <martin.barisits@cern.ch>, 2016-2020

import os
import sys

from distutils.command.sdist import sdist as _sdist  # pylint: disable=no-name-in-module,import-error

if sys.version_info < (2, 4):
    print('ERROR: Rucio requires at least Python 2.5 to run.')
    sys.exit(1)

sys.path.insert(0, os.path.abspath('lib/'))

from rucio import version  # noqa: E402

try:
    from setuptools import setup
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()

name = 'rucio-webui'
packages = ['rucio', 'rucio.web', 'rucio.web.ui', 'rucio.web.ui.common']
data_files = []
description = "Rucio WebUI Package"
IsRelease = True

# If Sphinx is installed on the box running setup.py,
# enable setup.py to build the documentation, otherwise,
# just ignore it
cmdclass = {}

try:
    from sphinx.setup_command import BuildDoc

    class local_BuildDoc(BuildDoc):
        def run(self):
            for builder in ['html']:   # 'man','latex'
                self.builder = builder
                self.finalize_options()
                BuildDoc.run(self)
    cmdclass['build_sphinx'] = local_BuildDoc
except:
    pass


class CustomSdist(_sdist):

    user_options = [
        ('packaging=', None, "Some option to indicate what should be packaged")
    ] + _sdist.user_options

    def __init__(self, *args, **kwargs):
        _sdist.__init__(self, *args, **kwargs)
        self.packaging = "default value for this option"

    def get_file_list(self):
        print("Chosen packaging option: " + name)
        self.distribution.data_files = data_files
        _sdist.get_file_list(self)


cmdclass['sdist'] = CustomSdist

setup(
    name=name,
    version=version.version_string(),
    packages=packages,
    package_dir={'': 'lib'},
    data_files=None,
    script_args=sys.argv[1:],
    cmdclass=cmdclass,
    include_package_data=True,
    scripts=None,
    # doc=cmdclass,
    author="Rucio",
    author_email="rucio-dev@cern.ch",
    description=description,
    license="Apache License, Version 2.0",
    url="http://rucio.cern.ch/",
    python_requires=">=3.6, !=3.9.*, <4",
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
        'Environment :: No Input/Output (Daemon)', ],
    install_requires=['rucio>=1.2.5', ],
    dependency_links=[],
)
