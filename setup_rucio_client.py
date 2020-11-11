# -*- coding: utf-8 -*-
# Copyright 2014-2020 CERN
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

import os
import re
import shutil
import subprocess
import sys

from distutils.command.sdist import sdist as _sdist  # pylint:disable=no-name-in-module,import-error
from setuptools import setup

sys.path.insert(0, os.path.abspath('lib/'))

from rucio import version  # noqa

if sys.version_info < (2, 5):
    print('ERROR: Rucio requires at least Python 2.6 to run.')
    sys.exit(1)
sys.path.insert(0, os.path.abspath('lib/'))


# Arguments to the setup script to build Basic/Lite distributions
COPY_ARGS = sys.argv[1:]
NAME = 'rucio-clients'
IS_RELEASE = False
PACKAGES = ['rucio', 'rucio.client', 'rucio.common', 'rucio.common.schema', 
            'rucio.rse.protocols', 'rucio.rse', 'rucio.tests']
REQUIREMENTS_FILES = ['etc/pip-requires-client']
DESCRIPTION = "Rucio Client Lite Package"
DATA_FILES = [('etc/', ['etc/rse-accounts.cfg.template', 'etc/rucio.cfg.template', 'etc/rucio.cfg.atlas.client.template',
                        'etc/pip-requires-client']),]

SCRIPTS = ['bin/rucio', 'bin/rucio-admin']
if os.path.exists('build/'):
    shutil.rmtree('build/')
if os.path.exists('lib/rucio_clients.egg-info/'):
    shutil.rmtree('lib/rucio_clients.egg-info/')
if os.path.exists('lib/rucio.egg-info/'):
    shutil.rmtree('lib/rucio.egg-info/')

SSH_EXTRAS = ['paramiko==1.18.4']
KERBEROS_EXTRAS = ['kerberos>=1.2.5', 'pykerberos>=1.1.14', 'requests-kerberos>=0.11.0']
SWIFT_EXTRAS = ['python-swiftclient>=3.5.0', ]
EXTRAS_REQUIRES = dict(ssh=SSH_EXTRAS,
                       kerberos=KERBEROS_EXTRAS,
                       swift=SWIFT_EXTRAS)

if '--release' in COPY_ARGS:
    IS_RELEASE = True
    COPY_ARGS.remove('--release')


# If Sphinx is installed on the box running setup.py,
# enable setup.py to build the documentation, otherwise,
# just ignore it
cmdclass = {}

try:
    from sphinx.setup_command import BuildDoc

    class local_BuildDoc(BuildDoc):
        '''
        local_BuildDoc
        '''
        def run(self):
            '''
            run
            '''
            for builder in ['html']:   # 'man','latex'
                self.builder = builder
                self.finalize_options()
                BuildDoc.run(self)
    cmdclass['build_sphinx'] = local_BuildDoc
except Exception:
    pass


def get_reqs_from_file(requirements_file):
    '''
    get_reqs_from_file
    '''
    if os.path.exists(requirements_file):
        return open(requirements_file, 'r').read().split('\n')
    return []


def parse_requirements(requirements_files):
    '''
    parse_requirements
    '''
    requirements = []
    for requirements_file in requirements_files:
        for line in get_reqs_from_file(requirements_file):
            if re.match(r'\s*-e\s+', line):
                requirements.append(re.sub(r'\s*-e\s+.*#egg=(.*)$', r'\1', line))
            elif re.match(r'\s*-f\s+', line):
                pass
            else:
                requirements.append(line)
    return requirements


def parse_dependency_links(requirements_files):
    '''
    parse_dependency_links
    '''
    dependency_links = []
    for requirements_file in requirements_files:
        for line in get_reqs_from_file(requirements_file):
            if re.match(r'(\s*#)|(\s*$)', line):
                continue
            if re.match(r'\s*-[ef]\s+', line):
                dependency_links.append(re.sub(r'\s*-[ef]\s+', '', line))
    return dependency_links


def write_requirements():
    '''
    write_requirements
    '''
    venv = os.environ.get('VIRTUAL_ENV', None)
    if venv is not None:
        req_file = open("requirements.txt", "w")
        output = subprocess.Popen(["pip", "freeze", "-l"], stdout=subprocess.PIPE)
        requirements = output.communicate()[0].strip()
        req_file.write(requirements)
        req_file.close()


REQUIRES = parse_requirements(requirements_files=REQUIREMENTS_FILES)
DEPEND_LINKS = parse_dependency_links(requirements_files=REQUIREMENTS_FILES)


class CustomSdist(_sdist):
    '''
    CustomSdist
    '''
    user_options = [
        ('packaging=', None, "Some option to indicate what should be packaged")
    ] + _sdist.user_options

    def __init__(self, *args, **kwargs):
        '''
        __init__
        '''
        _sdist.__init__(self, *args, **kwargs)
        self.packaging = "default value for this option"

    def get_file_list(self):
        '''
        get_file_list
        '''
        print("Chosen packaging option: " + NAME)
        self.distribution.data_files = DATA_FILES
        _sdist.get_file_list(self)


cmdclass['sdist'] = CustomSdist

# For using SSO login option, install these RPM packages: libxml2-devel xmlsec1-devel xmlsec1-openssl-devel libtool-ltdl-devel

setup(
    name=NAME,
    version=version.version_string(),
    packages=PACKAGES,
    package_dir={'': 'lib'},
    data_files=DATA_FILES,
    script_args=COPY_ARGS,
    cmdclass=cmdclass,
    include_package_data=True,
    scripts=SCRIPTS,
    # doc=cmdclass,
    author="Rucio",
    author_email="rucio-dev@cern.ch",
    description=DESCRIPTION,
    license="Apache License, Version 2.0",
    url="http://rucio.cern.ch/",
    python_requires=">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, !=3.5.*, !=3.9.*, <4",
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
    ],
    install_requires=REQUIRES,
    extras_require=EXTRAS_REQUIRES,
    dependency_links=DEPEND_LINKS,
)
