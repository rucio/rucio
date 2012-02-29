# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012


def add_replica(scope, lfn, rse, lfn_meta=None):
    """
    Creates a scope for an account.
    
    :param scope: The scope name.
    :parm  lfn: The file identifier(lfn).
    :parm  rse: The file location(rse).
    :param lfn_meta: Optional mapping of information about the file.                
    
    :returns: If the operation is successful a response code of "0" is returned. If an error occurs, a non zero response code is returned.
    """
    pass

def delete_replica(self, scope, lfn, rse):
    """
    Deletes rucio's information about a file replica.
    
    :param scope: The scope name.
    :parm  lfn: The file identifier(lfn).
    :parm  rse: The file location(rse).
    
    """
    pass


def list_replicas(self, **kwargs):
    """
    Returns a list of replica scope::lfn/rse mappins
    
    :param filters: dictionary of attributes by which the resulting
                    collection of replicas should be filtered
    :param limit: maximum number of items to return
    :param sort_key: results will be ordered by this image attribute
    :param sort_dir: direction in which to to order results (asc, desc)
    """
    pass

