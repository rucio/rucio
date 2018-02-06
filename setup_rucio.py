# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2011-2017
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012-2013
# - Martin Barisits, <martin.barisits@cern.ch>, 2016-2017

import glob
import os
import re
import subprocess
import sys

from distutils.command.sdist import sdist as _sdist

if sys.version_info < (2, 4):
    print('ERROR: Rucio requires at least Python 2.5 to run.')
    sys.exit(1)

sys.path.insert(0, os.path.abspath('lib/'))

from rucio import version  # noqa

try:
    from setuptools import setup, find_packages
#    from setuptools.command.sdist import sdist
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()

name = 'rucio'
packages = find_packages('lib/')
description = "Rucio Package"
IsRelease = False
requirements_files = ['tools/pip-requires', 'tools/pip-requires-client']
data_files = [('rucio/etc/', glob.glob('etc/*.template')),
              ('rucio/etc/web', glob.glob('etc/web/*.template')),
              ('rucio/etc/schemas', glob.glob('etc/schemas/*.json')),
              ('rucio/tools/', ['tools/pip-requires', 'tools/pip-requires-client', 'tools/pip-requires-test',
                                'tools/bootstrap.py', 'tools/reset_database.py']),
              ('rucio/tools/probes/common/', ['tools/probes/common/graphite2nagios', ]),
              ('rucio/tools/probes/common/', glob.glob('tools/probes/common/check*')),
              ('rucio/etc/mail_templates/', glob.glob('etc/mail_templates/*.tmpl'))]

scripts = glob.glob('bin/rucio*')

# Arguments to the setup script to build stable release
copy_args = sys.argv[1:]
if '--release' in copy_args:
    IsRelease = True
    copy_args.remove('--release')

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


def get_reqs_from_file(requirements_file):
    if os.path.exists(requirements_file):
        return open(requirements_file, 'r').read().split('\n')
    return []


def parse_requirements(requirements_files):
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
    dependency_links = []
    for requirements_file in requirements_files:
        for line in get_reqs_from_file(requirements_file):
            if re.match(r'(\s*#)|(\s*$)', line):
                continue
            if re.match(r'\s*-[ef]\s+', line):
                dependency_links.append(re.sub(r'\s*-[ef]\s+', '', line))
    return dependency_links


def write_requirements():
    venv = os.environ.get('VIRTUAL_ENV', None)
    if venv is not None:
        req_file = open("requirements.txt", "w")
        output = subprocess.Popen(["pip", "freeze", "-l"], stdout=subprocess.PIPE)
        requirements = output.communicate()[0].strip()
        req_file.write(requirements)
        req_file.close()


oracle_extras = ['cx_oracle>=5.1']
postgresql_extras = ['psycopg2>=2.4.2']
mysql_extras = ['PyMySQL']

requires = parse_requirements(requirements_files=requirements_files)
extras_require = dict(oracle=oracle_extras,
                      postgresql=postgresql_extras,
                      mysql=mysql_extras)
requires = parse_requirements(requirements_files=requirements_files)
depend_links = parse_dependency_links(requirements_files=requirements_files)


class CustomSdist(_sdist):

    user_options = [
        ('packaging=', None, "Some option to indicate what should be packaged")
    ] + _sdist.user_options

    def __init__(self, *args, **kwargs):
        _sdist.__init__(self, *args, **kwargs)
        self.packaging = "default value for this option"

    def get_file_list(self):
        print "Chosen packaging option: " + name
        self.distribution.data_files = data_files
        _sdist.get_file_list(self)


cmdclass['sdist'] = CustomSdist

setup(
    name=name,
    version=version.version_string(),
    packages=packages,
    package_dir={'': 'lib'},
    data_files=data_files,
    script_args=copy_args,
    cmdclass=cmdclass,
    include_package_data=True,
    scripts=scripts,
    # doc=cmdclass,
    author="Rucio",
    author_email="rucio-dev@cern.ch",
    description=description,
    license="Apache License, Version 2.0",
    url="http://rucio.cern.ch/",
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: Apache Software License',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Operating System :: POSIX :: Linux',
        'Natural Language :: English',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Environment :: No Input/Output (Daemon)', ],
    install_requires=requires,
    extras_require=extras_require,
    dependency_links=depend_links,
)
