=======================
Install gfal2 on Debian
=======================


The best supported file transfer backend for Rucio is the CERN General
File Access Library version 2, or *gfal2* for short.  It is in itself
a modular multi-protocol library which provides plugins for the most
common transfer protocols, including WebDAV, GridFTP (also known as
gsiftp), SRM, and others.

The *gfal2* library and transfer protocol plugins are available in the
Debian repositories. Rucio and the command line utilities use the
Python bindings however, and those have to be installed from source
with pip.


## Install gfal2 library

It turned out that only the unstable version is compatible with the
most recent Python binding sources. At first I installed the stable
version, whereafter compilation as below failed with error messages
about undefined types or missing headers. Thus, install the packages
like this from the *sid* repository.


    sudo apt -t sid install gfal2 libgfal2-dev


## Install gfal2 Python bindings

There are several dependencies that must be installed in order to
compile the Python bindings. Install dev packages as necessary; see
documentation in the *gfal2-python* source distribution.  It may also be
necessary to run:

    pip3 install wheel

Otherwise the procedure is the usual one:

    git clone git@github.com:cern-fts/gfal2-python
	
	cd gfal2-python
	
Check the README and any other documentation regarding the
dependencies you have to install.
	
	[sudo] pip3 install .

This should complete without errors.

Note: if you are running the Rucio client from a Python virtual
environment, run this install in the same environment or Python may
fail to find the *gfal2* library. Otherwise install system-wide as
root/sudo.

	
## Install gfal2 CLIs

The *gfal2* Python library installed as above should be enough in order
to use the Rucio *gfal.py* transfer plugin. However, you may want the
*gfal-\** command line utilities to test that access to storage
works. These commands are simply Python scripts wrapping the *gfal2*
library.  Install them in the same way:

    git clone git@github.com:cern-fts/gfal2-util
   
    cd gfal2-util
   
    pip3 install .
   
   
## Testing your GridFTP server
   
If this install is successful you will be able to use the *gfal2*
tools from the command line. Some examples (remember to create a proxy
certificate first or set the path to your client certificate):

    gfal-ls gsiftp://my.gridftp.server/home/user/ 
	
	gfal-copy somefile.dat gsiftp://my.gridftp.server/home/user/somefile.dat


Note for GEANT Sectigo certificate users: It is important that the
host certificate of the GridFTP server is of the *IGTF* grid
certificate type, which has a different intermediate CA chain than for
example the OV certifiates. If not, connection will fail with error
messages about DNs of CAs missing from the signing policies, etc.

