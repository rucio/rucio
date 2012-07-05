# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2012

import json
import os
import pprint

from rucio.common import exception

path_to_repo = {'global': 'etc/rse.repository', 'local': []}


def transfer(source, dest, lfns):
    """ Transfers files from source storage system to destination storage system.

    :param source RSE whre the files are taken from
    :param dest RSE where the files shoudl be transfered to
    :param lfns Array representing all files to be transfered
    """

    #TODO: Implement it when there is more information about site transfers
    raise NotImplementedError


def add_local_repository(path):
    """ Adds a local repository file to choose storage systems from.

    :param path Path to the local repository defintion
    """
    if os.path.isfile(path):
        path_to_repo['local'].append(path)
    else:
        raise exception.RSERepositoryNotFound('Local repository %s not found' % path)


class RucioStorageElement(object):
    """ An RSE represents a specfic storage system. Each interaction with
    the files stored inside it should be done using RSE objects.
    """

    def __init__(self, **kwarg):
        """ Contructor method for RSE objects.

            If no parameter is provided, the method selectes a storage
            system autmatically depending on the current situation.

            It is further supported to redefine properties defined inside the
            repository for this RSE instance only. iTo do so they must be provide as parameters
            of the constructer or re-define afterwards by changing the properties instance, dynamic,
            or static.

            :param id       ID of the site in the repository
            :param protocol ID of the protocol if an other than the default for this storage schould be used
            :param pwd      Path to the directory where downloaded files should be stored
        """
        # sets the repo-data for the object
        self.instance = {}
        self.dynamic = {}
        self.static = {}
        if 'id' in kwarg:
            self.instance['site_id'] = kwarg['id']
            self.__get_repo_data()  # May throw an 404 exception
            self.instance['protocol_id'] = self.static['protocols']['default']  # Set the protocol to the default one
        else:
            self.instance['site_id'] = 'auto_select'
        # Setting defaults and copy remaining attributes into properties object
        self.instance['connected'] = False
        self.instance['pwd'] = os.getcwd()
        for arg in kwarg:
            if arg != 'id' and arg != 'protocol':
                self.instance[arg] = kwarg[arg]
        # determine protocol
        if ('protocol' in kwarg) and (kwarg['protocol'] != self.instance['protocol_id']):
            self.instance['protocol_id'] = None
            # Searching alternative protocols
            for p in self.static['protocols']['supported']:
                if p == kwarg['protocol']:
                    self.instance['protocol_id'] = kwarg['protocol']
        if self.instance['protocol_id'] == None:
            raise exception.SwitchProtocols({'protocols': json.dumps(self._rse_properties['static']['protocols'])})
        self.__create_protocol_instance()

    def __get_repo_data(self):
        """ Initilaizes the object with the data provided by the repository about
            the storage system reffered by ID.
        """
        data = json.load(open(path_to_repo['global']))
        try:
            for loc_repo in path_to_repo['local']:
                data.update(json.load(open(loc_repo)))
        except Exception as e:
            raise exception.RSERepositoryNotFound({'repos': path_to_repo, 'exception': e})
        if self.instance['site_id'] in data:
            self.dynamic = data[self.instance['site_id']]['dynamic']
            self.static = data[self.instance['site_id']]['static']
        else:
            raise exception.RSENotFound('RSE %s not found in %s' % (self.instance['site_id'], path_to_repo))

    def __create_protocol_instance(self):
        """ Instantiates the protocol class defined in the object. """
        parts = ('rucio.rse.protocols.' + self.instance['protocol_id']).split('.')
        module = ".".join(parts[:-1])
        m = __import__(module)
        for comp in parts[1:]:
            m = getattr(m, comp)
        self.instance['protocol'] = m(self)

    def __str__(self):
        """ Print information about the referred storage system. """
        s = '=' * 80 + '\n'
        s += '-' * 34 + ' RSE Object ' + '-' * 34 + '\n'
        s += '-' * 27 + ' RSE Porperties - INSTANCE' + '-' * 27 + '\n'
        s += pprint.PrettyPrinter(indent=4).pformat(self.instance) + '\n'
        s += '-' * 28 + ' RSE Porperties - STATIC' + '-' * 28 + '\n'
        s += pprint.PrettyPrinter(indent=4).pformat(self.static) + '\n'
        s += '-' * 28 + ' RSE Porperties - DYNAMIC' + '-' * 27 + '\n'
        s += pprint.PrettyPrinter(indent=4).pformat(self.dynamic) + '\n'
        s += '=' * 80
        return s

    def __lfn2pfn(self, lfn):
        """ Transform the logical file name into the physical file name.

            :param lfn Logical file name
            :returns: iPhysical file name
        """
        # do some voodoo e.g. pfn = md5.md5(lfn)
        pfn = lfn
        return pfn

    def lfn2uri(self, lfn):
        """ Derives the storage specific URI to the given physical file name.

            :param lfn Logical file name
            :returns: Storage specific URI of the specified file
        """
        tmp = self.__lfn2pfn(lfn)
        return self.instance['protocol'].pfn2uri(tmp)

    def __register_file(self, lfn):
        """ Registers a new file at the central catalogue.

            :param lfn Logical file name of the to be registered file
        """
        # TODO: Register in cerntral catalogue
        pass

    def __unregister_file(self, lfn):
        """ Unregisters data from the central catalogue.

            :param lfn Logical file name of the to be unregistered file
        """
        # TODO: Call Unregister method from protocol
        pass

    def connect(self, credentials):
        """ Establishes the connection tothe referred storage system.

            :param credentials Provides all necessary information to connect to the
            referred storage using the defined protocol. See documentation of the actual
            protocol for more information about this parameter.
        """
        self.instance['protocol'].connect(credentials) if not self.instance['connected'] else None
        self.instance['connected'] = True

    def close(self):
        """ Closes the connection to the storage system. """
        self.instance['protocol'].close() if self.instance['connected'] else None
        self.instance['connected'] = False

    def get(self, lfns, dest=None):
        """ Copies files from the referred storage system to the local file system.

            :param lfns Logical file names, can be either one string or an array of strings
        """
        lfns = [lfns] if type(lfns) is str else lfns
        dest_file = ''
        if dest != None:
            dest_file = dest
        for lfn in lfns:
            # TODO: Must the central catalogue be checked here?
            # TODO: create a thread for each file
            pfn = self.__lfn2pfn(lfn)
            # TODO: Populate popularity stuff
            self.instance['protocol'].get(pfn, dest_file + lfn)

    def put(self, lfns, source_path=None):
        """ Uploads files from the local filesystem to the referred storage system.

            :param lfns Logical file names, can be either one string or an array of strings
        """
        lfns = [lfns] if type(lfns) is str else lfns
        for lfn in lfns:
            # TODO: Must the central catalogue be check here?
            # TODO: create a thread for each file?
            self.instance['protocol'].put(self.__lfn2pfn(lfn), source_path)  # Also registers file in local catalogue of the storage if necessary
            self.__register_file(lfn)  # Happens only if put didn't fail

    def delete(self, lfns):
        """ Deletes a file from the referred storage system.

            :param lfns Logical file names, can be either one string or an array of strings
        """
        lfns = [lfns] if type(lfns) is str else lfns
        for lfn in lfns:
            # TODO: Must the central catalogue be check here?
            # TODO: create a thread for each file
            pfn = self.__lfn2pfn(lfn)
            if self.instance['protocol'].exists(pfn):
                self.instance['protocol'].delete(pfn)
                self.__unregister_file(lfn)  # Happens only if put didn't fail
            else:
                raise exception.FileNotFound('File %s not found at given storage system.' % lfn)

    def exists(self, lfns):
        """ Checks if given files exist on referred storage system.

            :param lfns Logical file names, can be either one string or an array of strings
        """
        lfns = [lfns] if type(lfns) is str else lfns
        for lfn in lfns:
            if not self.instance['protocol'].exists(self.__lfn2pfn(lfn)):
                return False
        return True
