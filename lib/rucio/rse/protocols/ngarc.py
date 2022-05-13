# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

import errno
import os

from rucio.common.exception import FileAlreadyExists, ServiceUnavailable, SourceNotFound
from rucio.rse.protocols import protocol

try:
    import arc  # pylint: disable=import-error
except:
    pass


class DataPoint:
    '''
    Wrapper around arc.datapoint_from_url() which does not clean up DataPoints
    when python objects are destroyed, leading to connection leaking when used
    with gridftp. This class should be used instead of arc.datapoint_from_url().
    It can be called like dp = DataPoint('gsiftp://...', uc); dp.h.Stat()
    where uc is an arc.UserConfig object.
    '''
    def __init__(self, u, uc):
        self.h = arc.datapoint_from_url(u, uc)

    def __del__(self):
        arc.DataPoint.__swig_destroy__(self.h)


class Default(protocol.RSEProtocol):
    """ Implementing access to RSEs using ARC client."""

    def __init__(self, protocol_attr, rse_settings, logger=None):
        """
        Set up UserConfig object.
        """
        super(Default, self).__init__(protocol_attr, rse_settings, logger=logger)

        # Arc logging to stdout, uncomment for debugging. Should use root
        # logger level eventually.
#         root_logger = arc.Logger_getRootLogger()
#         stream = arc.LogStream(sys.stdout)
#         root_logger.addDestination(stream)
#         # Set threshold to VERBOSE or DEBUG for more information
#         root_logger.setThreshold(arc.DEBUG)

        self.cfg = arc.UserConfig()
        try:
            self.cfg.ProxyPath(os.environ['X509_USER_PROXY'])
        except:
            pass

    def path2pfn(self, path):
        """
            Retruns a fully qualified PFN for the file referred by path.

            :param path: The path to the file.

            :returns: Fully qualified PFN.

        """
        return ''.join([self.rse['scheme'], '://%s' % self.rse['hostname'], path])

    def exists(self, pfn):
        """ Checks if the requested file is known by the referred RSE.

            :param pfn: Physical file name

            :returns: True if the file exists, False if it doesn't

            :raise  ServiceUnavailable
        """
        dp = DataPoint(str(pfn), self.cfg)
        fileinfo = arc.FileInfo()

        status = dp.h.Stat(fileinfo)
        if not status:
            if status.GetErrno() == errno.ENOENT:
                return False
            raise ServiceUnavailable(str(status))

        return True

    def connect(self):
        """ Establishes the actual connection to the referred RSE.

            :raise RSEAccessDenied
        """
        pass

    def close(self):
        """ Closes the connection to RSE."""
        pass

    def __arc_copy(self, src, dest, space_token=None, transfer_timeout=None):

        # TODO set proxy path

        # Convert the arguments to DataPoint objects
        source = DataPoint(str(src), self.cfg)
        if source.h is None:
            raise ServiceUnavailable("Can't handle source %s" % src)

        destination = DataPoint(str(dest), self.cfg)
        if destination.h is None:
            raise ServiceUnavailable("Can't handle destination %s" % dest)
        if space_token:
            destination.h.GetURL().AddOption('spacetoken', space_token)

        # DataMover does the transfer
        mover = arc.DataMover()
        # Don't attempt to retry on error
        mover.retry(False)
        # Passive and insecure gridftp
        mover.passive(True)
        mover.secure(False)
        # Do the transfer
        status = mover.Transfer(source.h, destination.h, arc.FileCache(), arc.URLMap())

        if not status:
            if status.GetErrno() == errno.ENOENT:
                raise SourceNotFound()
            if status.GetErrno() == errno.EEXIST:
                raise FileAlreadyExists()
            raise ServiceUnavailable(str(status))

    def get(self, pfn, dest, transfer_timeout=None):
        """ Provides access to files stored inside connected the RSE.

            :param pfn: Physical file name of requested file
            :param dest: Name and path of the files when stored at the client
            :param transfer_timeout Transfer timeout (in seconds) - dummy

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound
        """
        self.__arc_copy(pfn, dest, transfer_timeout=transfer_timeout)

    def put(self, source, target, source_dir=None, transfer_timeout=None):
        """ Allows to store files inside the referred RSE.

            :param source: Physical file name
            :param target: Name of the file on the storage system e.g. with prefixed scope
            :param source_dir Path where the to be transferred files are stored in the local file system
            :param transfer_timeout Transfer timeout (in seconds) - dummy

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound
        """

        if source_dir:
            sf = source_dir + '/' + source
        else:
            sf = source

        space_token = None
        if self.attributes['extended_attributes'] is not None and 'space_token' in list(self.attributes['extended_attributes'].keys()):
            space_token = self.attributes['extended_attributes']['space_token']

        self.__arc_copy(sf, target, space_token, transfer_timeout=transfer_timeout)

    def delete(self, pfn):
        """ Deletes a file from the connected RSE.

            :param pfn: Physical file name

            :raises ServiceUnavailable, SourceNotFound
        """
        dp = DataPoint(str(pfn), self.cfg)
        if dp.h is None:
            raise ServiceUnavailable("Can't handle pfn %s" % pfn)

        status = dp.h.Remove()
        if not status:
            if status.GetErrno() == errno.ENOENT:
                raise SourceNotFound()
            raise ServiceUnavailable(str(status))

    def rename(self, pfn, new_pfn):
        """ Allows to rename a file stored inside the connected RSE.

            :param pfn:      Current physical file name
            :param new_pfn  New physical file name

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound
        """
        dp = DataPoint(str(pfn), self.cfg)
        if dp.h is None:
            raise ServiceUnavailable("Can't handle pfn %s" % pfn)

        url = arc.URL(str(new_pfn))
        if not url:
            raise ServiceUnavailable("Can't handle new pfn %s" % new_pfn)

        status = dp.h.Rename(url)
        if not status:
            if status.GetErrno() == errno.ENOENT:
                raise SourceNotFound()
            raise ServiceUnavailable(str(status))
