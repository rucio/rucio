"""
@copyright: European Organization for Nuclear Research (CERN)
@contact: U{ph-adp-ddm-lab@cern.ch<mailto:ph-adp-ddm-lab@cern.ch>}
@license: Licensed under the Apache License, Version 2.0 (the "License");
You may not use this file except in compliance with the License.
You may obtain a copy of the License at U{http://www.apache.org/licenses/LICENSE-2.0}
@author:
- Vincent Garonne, <vincent.garonne@cern.ch>, 2011

"""
import gettext
import glob
import shutil
import os, sys
import subprocess

if sys.version_info < (2, 4):
    print('ERROR: Rucio requires at least Python 2.5 to run.')
    sys.exit(1)

sys.path.insert(0, os.path.abspath('lib/'))

from rucio import version

try:
  from setuptools               import setup, find_packages
  from setuptools.command.sdist import sdist
except ImportError:
  from ez_setup import use_setuptools
  use_setuptools()
  from setuptools import setup, find_packages

# In order to run the i18n commands for compiling and
# installing message catalogs, we use DistUtilsExtra.
# Don't make this a hard requirement, but warn that
# i18n commands won't be available if DistUtilsExtra is
# not installed...
#try:
#    from DistUtilsExtra.auto import setup
#except ImportError:
#    from setuptools import setup
#    print "Warning: DistUtilsExtra required to use i18n builders. "
#    print "To build rucio with support for message catalogs, you need "
#    print "  https://launchpad.net/python-distutils-extra >= 2.18"


name        = 'rucio'
packages    = find_packages('lib/')
description = "Rucio Package"

# Arguments to the setup script to build Basic/Lite distributions
copy_args = sys.argv[1:]
if '--client' in copy_args:
  name        = 'rucio-client'
  packages    = ['rucio.client',]
  description = "Rucio Client Lite Package"
  shutil.rmtree('build/')
  copy_args.remove('--client')


def run_git_command(cmd):
    output = subprocess.Popen(["/bin/sh", "-c", cmd],
                              stdout=subprocess.PIPE)
    return output.communicate()[0].strip()


if os.path.isdir('.git'):
    branch_nick_cmd = 'git branch | grep -Ei "\* (.*)" | cut -f2 -d" "'
    branch_nick = run_git_command(branch_nick_cmd)
    revid_cmd = "git --no-pager log --max-count=1 | cut -f2 -d' ' | head -1"
    revid = run_git_command(revid_cmd)
    revno_cmd = "git --no-pager log --oneline | wc -l"
    revno = run_git_command(revno_cmd)
    version_file = open("lib/rucio/vcsversion.py", 'w')
    version_file.write("""
# This file is automatically generated by setup.py, So don't edit it. :)
version_info = {
    'branch_nick': '%s',
    'revision_id': '%s',
    'revno': %s
}
""" % (branch_nick, revid, revno))
    version_file.close ()

# If Sphinx is installed on the box running setup.py,
# enable setup.py to build the documentation, otherwise,
# just ignore it
cmdclass = {}

try:
    from sphinx.setup_command import BuildDoc

    class local_BuildDoc(BuildDoc):
        def run(self):
            for builder in ['html', 'man']:
                self.builder = builder
                self.finalize_options()
                BuildDoc.run(self)
    cmdclass['build_sphinx'] = local_BuildDoc
except:
    pass


setup(
      name                 = name,
      version              = version.canonical_version_string(),
#      version              = version.version_string(),
#      version              = version.vcs_version_string(),
#      version              = version.version_string_with_vcs(),
      packages             = packages,
      package_dir          = {'': 'lib'},
      script_args          = copy_args,
      cmdclass             = cmdclass,
      include_package_data = True,
      data_files           = [('doc/',),] ,
      scripts              =['bin/rucio',
                             'bin/rucio-admin'],
      #doc                 = cmdclass,
      author               = "Vincent Garonne",
      author_email         = "vincent.garonne@cern.ch",
      description          = description,
      license              = "Apache License, Version 2.0",
      url                  = "http://rucio.cern.ch/",
      classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2.6',
        'Environment :: No Input/Output (Daemon)',
    ],
)
