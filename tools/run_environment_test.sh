#!/bin/bash
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012

# This simple script scratches everything and tries to build Rucio from the origin master,
# including all dependencies. Just make an empty directory somewhere, copy this script into it,
# and run it. It should end with a lot of "OK" messages.
#
# Caveat emptor:
# - On linux systems, it is assumed that the ATLAS algebra libraries are installed
#   (this is usually the case on SLC machines). If they are not there, install them
#   with "yum install atlas atlas-devel"
# - On darwin systems, we assume that they are 64-bit by default, which is true since
#   Snow Leopard. Previous versions that are 32-bit by default but have the 64-bit libraries
#   installed should work, but are not tested.
#
# TODO: Replace all the "building stuff from source" with proper packages. (current runtime: ~250 seconds)

PYVERSIONFULL=2.7.2
PYVERSION=${PYVERSIONFULL:0:3}
EASYINSTALLVERSION=0.6c11

now=`date +%Y-%m-%d-%H-%M-%S`

if [[ ! -e python-$PYVERSIONFULL ]]; then
 echo
 echo "Installing Python $PYVERSION - This can take some time..."
 curl -sO http://python.org/ftp/python/$PYVERSIONFULL/Python-$PYVERSIONFULL.tar.bz2
 tar xfj Python-$PYVERSIONFULL.tar.bz2
 cd Python-$PYVERSIONFULL
 ./configure --prefix=`dirname $PWD`/python-$PYVERSIONFULL
 make
 make install
 cd ..
 rm -rf Python-$PYVERSIONFULL.tar.bz2
fi
export PATH=$PWD/python-$PYVERSIONFULL/bin:$PATH

echo
echo "Installing prerequisites"
curl -s "http://pypi.python.org/packages/source/s/setuptools/setuptools-0.6c11.tar.gz#md5=7df2a529a074f613b509fb44feefe74e" > /tmp/setuptools-0.6c11.tar.gz
tar xfz /tmp/setuptools-0.6c11.tar.gz
cd setuptools-0.6c11
python$PYVERSION setup.py install >/dev/null 2>&1
cd ..
rm -rf setuptools-0.6c11 /tmp/setuptools-0.6c11.tar.gz
easy_install-$PYVERSION pip >/dev/null 2>&1
pip-$PYVERSION install virtualenv >/dev/null 2>&1

echo
echo "Removing old runs"
rm -rf 201*

echo
echo "Checking out origin master"
export GIT_SSL_NO_VERIFY=1
git clone https://atlas-gerrit.cern.ch:8443/p/rucio $now >/dev/null 2>&1
cd $now

echo
echo "Installing oracle instantclient"
mkdir oracle-instantclient
cd oracle-instantclient
if [[ `uname` == 'Darwin' ]]; then
 ORAVERSION=10.2.0.4.0
 ORAARCH=macosx
 ORADIR=10_2
elif [[ `uname` == 'Linux' ]]; then
 ORAVERSION=11.2.0.3.0
 ORAARCH=linux
 ORADIR=11_2
fi
curl -sO http://bourricot.cern.ch/oracle/instantclient-basic-$ORAARCH.x64-$ORAVERSION.zip
unzip -qq instantclient-basic-$ORAARCH.x64-$ORAVERSION.zip
curl -sO http://bourricot.cern.ch/oracle/instantclient-sqlplus-$ORAARCH.x64-$ORAVERSION.zip
unzip -qq instantclient-sqlplus-$ORAARCH.x64-$ORAVERSION.zip
curl -sO http://bourricot.cern.ch/oracle/instantclient-jdbc-$ORAARCH.x64-$ORAVERSION.zip
unzip -qq instantclient-jdbc-$ORAARCH.x64-$ORAVERSION.zip
curl -sO http://bourricot.cern.ch/oracle/instantclient-sdk-$ORAARCH.x64-$ORAVERSION.zip
unzip -qq instantclient-sdk-$ORAARCH.x64-$ORAVERSION.zip
if [[ `uname` == 'Darwin' ]]; then
 cd instantclient_10_2
 cp libclntsh.dylib.10.1 libclntsh.dylib
 export DYLD_LIBRARY_PATH=$PWD:$DYLD_LIBRARY_PATH
elif [[ `uname` == 'Linux' ]]; then
 cd instantclient_11_2
 cp libclntsh.so.11.1 libclntsh.so
 export LD_LIBRARY_PATH=$PWD:$LD_LIBRARY_PATH
fi
export PATH=$PWD:$PATH
cd ../..

echo
echo "Installing and activating venv with cx_Oracle failsafe - This can take some time..."
python$PYVERSION tools/install_venv.py >/dev/null 2>&1
source .venv/bin/activate
if [[ `uname` == 'Darwin' ]]; then
 export PATH=$PWD/oracle-instantclient/instantclient_10_2:$PATH
 export DYLD_LIBRARY_PATH=$PWD/oracle-instantclient/instantclient_10_2:$DYLD_LIBRARY_PATH
elif [[ `uname` == 'Linux' ]]; then
 export PATH=$PWD/oracle-instantclient/instantclient_11_2:$PATH
 export LD_LIBRARY_PATH=$PWD/oracle-instantclient/instantclient_11_2:$LD_LIBRARY_PATH
fi
pip-$PYVERSION install cx_Oracle >/dev/null 2>&1

echo
echo "Building documentation"
python$PYVERSION setup.py build_sphinx >/dev/null 2>&1

echo
echo "Are the imports alright?"
/bin/echo -n "cx_Oracle:       "; python -c "import cx_Oracle" >/dev/null 2>&1; if [[ $? == 1 ]]; then echo "NOT OK"; else echo "OK"; fi
/bin/echo -n "sqlalchemy:      "; python -c "import sqlalchemy" >/dev/null 2>&1; if [[ $? == 1 ]]; then echo "NOT OK"; else echo "OK"; fi
/bin/echo -n "sphinx:          "; python -c "import sphinx" >/dev/null 2>&1; if [[ $? == 1 ]]; then echo "NOT OK"; else echo "OK"; fi
/bin/echo -n "pygments:        "; python -c "import pygments" >/dev/null 2>&1; if [[ $? == 1 ]]; then echo "NOT OK"; else echo "OK"; fi
/bin/echo -n "jinja2:          "; python -c "import jinja2" >/dev/null 2>&1; if [[ $? == 1 ]]; then echo "NOT OK"; else echo "OK"; fi
/bin/echo -n "docutils:        "; python -c "import docutils" >/dev/null 2>&1; if [[ $? == 1 ]]; then echo "NOT OK"; else echo "OK"; fi
/bin/echo -n "pep8:            "; python -c "import pep8" >/dev/null 2>&1; if [[ $? == 1 ]]; then echo "NOT OK"; else echo "OK"; fi
/bin/echo -n "multi-mechanize: "; python -c "import mechanize" >/dev/null 2>&1; if [[ $? == 1 ]]; then echo "NOT OK"; else echo "OK"; fi
/bin/echo -n "numpy:           "; python -c "import numpy" >/dev/null 2>&1; if [[ $? == 1 ]]; then echo "NOT OK"; else echo "OK"; fi
/bin/echo -n "matplotlib:      "; python -c "import matplotlib" >/dev/null 2>&1; if [[ $? == 1 ]]; then echo "NOT OK"; else echo "OK"; fi
/bin/echo -n "rucio:           "; python -c "import rucio" >/dev/null 2>&1; if [[ $? == 1 ]]; then echo "NOT OK"; else echo "OK"; fi

deactivate
