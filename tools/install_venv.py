# Copyright 2011-2020 CERN for the benefit of the ATLAS collaboration.
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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2011-2013
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012
# - Martin Barisits <martin.barisits@cern.ch>, 2017-2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
# - Gabriele Gaetano Fronze' <gabriele.fronze@to.infn.it>, 2020

"""
Installation script Rucio's development virtualenv
"""

import sys
import os.path
base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_path)
os.chdir(base_path)

from __future__ import print_function  # noqa: E402, F404

import errno  # noqa: E402
import optparse  # noqa: E402
import os  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
VENV = os.path.join(ROOT, '.venv')
PIP_REQUIRES = os.path.join(ROOT, 'etc', 'pip-requires')
PIP_REQUIRES_CLIENT = os.path.join(ROOT, 'etc', 'pip-requires-client')
PIP_REQUIRES_TEST = os.path.join(ROOT, 'etc', 'pip-requires-test')


def die(message, *args):
    print(message % args, file=sys.stderr)
    sys.exit(1)


def run_command(cmd, redirect_output=True, check_exit_code=True, shell=False):
    """
    Runs a command in an out-of-process shell, returning the
    output of that command.  Working directory is ROOT.
    """
    if redirect_output:
        stdout = subprocess.PIPE
    else:
        stdout = None

    proc = subprocess.Popen(cmd, cwd=ROOT, stdout=stdout, shell=shell)
    output = proc.communicate()[0]
    if check_exit_code and proc.returncode != 0:
        die('Command "%s" failed.\n%s', ' '.join(cmd), output)
    return output


HAS_EASY_INSTALL = bool(run_command(['which', 'easy_install'], check_exit_code=False).strip())
HAS_VIRTUALENV = bool(run_command(['which', 'virtualenv'], check_exit_code=False).strip())
HAS_PIP = bool(run_command(['which', 'pip'], check_exit_code=False).strip())
HAS_CURL = bool(run_command(['which', 'curl'], check_exit_code=False).strip())


def check_dependencies():
    """Make sure virtualenv is in the path."""

    if not HAS_VIRTUALENV:
        print('virtualenv not found.')
        # Try installing it via curl/pip/easy_install...
        if HAS_PIP:
            print('Installing virtualenv via pip...', end=' ')
            if not run_command(['which', 'pip']):
                die('ERROR: virtualenv not found.\n\n'
                    'Rucio development requires virtualenv, please install'
                    ' it using your favorite package management tool')
            else:
                if not run_command(['pip', 'install', 'virtualenv']).strip():
                    die("Failed to install virtualenv.")
            print('done.')
        elif HAS_EASY_INSTALL:
            print('Installing virtualenv via easy_install...', end=' ')
            if not run_command(['which', 'easy_install']):
                die('ERROR: virtualenv not found.\n\n'
                    'Rucio development requires virtualenv, please install'
                    ' it using your favorite package management tool')
            else:
                if not run_command(['easy_install', 'virtualenv']).strip():
                    die("Failed to install virtualenv.")
            print('done.')
    print('done.')


def create_virtualenv(venv=VENV):
    """
    Creates the virtual environment and installs PIP only into the
    virtual environment
    """
    if HAS_VIRTUALENV:
        print('Creating venv...')
        run_command(['virtualenv', '-q', '--no-site-packages', VENV])
    elif HAS_CURL:
        print('Creating venv via curl...', end=' ')
        if not run_command("curl -s https://raw.github.com/pypa/virtualenv/master/virtualenv.py | %s - --no-site-packages %s" % (sys.executable, VENV), shell=True):
            die('Failed to install virtualenv with curl.')
    print('done.')
    print('Installing pip in virtualenv...', end=' ')
    if not run_command(['tools/with_venv.sh', 'pip', 'install', 'pip>=9.0.1']).strip():
        die("Failed to install pip.")
    print('done.')


def install_dependencies(venv=VENV, client=False):
    print('Installing dependencies with pip (this can take a while)...')

    run_command(['.venv/bin/pip', 'install', '-r', PIP_REQUIRES_CLIENT], redirect_output=False)

    if not client:
        run_command(['.venv/bin/pip', 'install', '-r', PIP_REQUIRES], redirect_output=False)

    run_command(['.venv/bin/pip', 'install', '-r', PIP_REQUIRES_TEST], redirect_output=False)

    # Tell the virtual env how to "import rucio"
    py_ver = _detect_python_version(venv)
    pthfile = os.path.join(venv, "lib", py_ver, "site-packages", "rucio.pth")
    f = open(pthfile, 'w')
    f.write("%s/lib/\n" % ROOT)
    f.close()


def _detect_python_version(venv):
    lib_dir = os.path.join(venv, "lib")
    for pathname in os.listdir(lib_dir):
        if pathname.startswith('python'):
            return pathname
    raise Exception('Unable to detect Python version')


def create_symlinks(venv=VENV, atlas_clients=False):
    print('Installing binaries symlinks ...')
    bin_dir = os.path.join(ROOT, "bin")
    venv_bin_dir = os.path.join(venv, "bin")
    binaries = os.listdir(bin_dir)
    for binary in binaries:
        source = os.path.join(bin_dir, binary)
        link_name = os.path.join(venv_bin_dir, binary)
        try:
            os.path.exists(link_name) and source != os.readlink(link_name)
        except OSError as e:
            if e.errno == errno.EINVAL:
                print('Delete broken symlink: %(link_name)s -> %(source)s' % locals())
                os.remove(link_name)
            else:
                raise e
        if not os.path.exists(link_name):
            print('Create the symlink: %(link_name)s -> %(source)s' % locals())
            os.symlink(source, link_name)

    if atlas_clients:
        source = os.path.join(ROOT, "etc")
        link_name = os.path.join(venv, "etc")
        try:
            os.path.exists(link_name) and source != os.readlink(link_name)
        except OSError as e:
            if e.errno == errno.EINVAL:
                print('Delete broken symlink: %(link_name)s -> %(source)s' % locals())
                os.remove(link_name)
            else:
                raise e
        if not os.path.exists(link_name):
            print('Create the symlink: %(link_name)s -> %(source)s' % locals())
            os.symlink(source, link_name)

        cfg_name = os.path.join(link_name, 'rucio.cfg')
        tpl_cfg_name = os.path.join(link_name, 'rucio.cfg.template')
        if not os.path.exists(cfg_name):
            print('Configuring Rucio with etc/rucio.cfg.template')
            shutil.copy(src=tpl_cfg_name, dst=cfg_name)


def print_help():
    help = """
 Rucio development environment setup is complete.

 Rucio development uses virtualenv to track and manage Python dependencies
 while in development and testing.

 To activate the Rucio virtualenv for the extent of your current shell session
 you can run:

 $ source .venv/bin/activate

 Or, if you prefer, you can run commands in the virtualenv on a case by case
 basis by running:

 $ tools/with_venv.sh <your command>

 Also, make test will automatically use the virtualenv.
    """
    print(help)


if __name__ == '__main__':

    parser = optparse.OptionParser()
    parser.add_option("-a", "--atlas-clients", action="store_true", default=False, dest="atlas_clients", help="Setting up a Rucio development environment for ATLAS clients")
    (options, args) = parser.parse_args()
    # check_dependencies()
    create_virtualenv()
    install_dependencies(client=options.atlas_clients)
    create_symlinks(atlas_clients=options.atlas_clients)
    print_help()
