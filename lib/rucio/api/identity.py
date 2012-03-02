# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012


def add_identity(identity, type):
        """
        Creates an user identity.

        :param identity: The identity key name.
        :param type: The type of the authentication,e.g. x509, gss.

        :returns: If the operation is successful a response code of "0" is returned. If an error occurs, a non zero response code is returned.
        """
        pass

def delete_identity(identity, type):
        """
        Deletes an user identity.

        :param identity: The identity key name.
        :param type: The type of the authentication,e.g. x509, gss.

        :returns: If the operation is successful a response code of "0" is returned. If an error occurs, a non zero response code is returned.
        """
        pass

def add_account_member(self, identity, type, account, default=False):
        """
        Adds a membership association between identity and account.

        :param identity: The identity key name.
        :param type:     The type of the authentication,e.g. x509, gss.
        :param account: The account name.
        :parm  default: If True, the account should be used by default with the provided identity.

        :returns: If the operation is successful a response code of "0" is returned. If an error occurs, a non zero response code is returned.

        """
        pass

def list_identities(**kwargs):
        """
        Returns a list of identities

        :param filters: dictionary of attributes by which the resulting
                        collection of identities should be filtered
        :param limit: maximum number of items to return
        :param sort_key: results will be ordered by this rse attribute
        :param sort_dir: direction in which to to order results (asc, desc)

        :returns: If the operation is successful a response code of "0" is returned. If an error occurs, a non zero response code is returned.
        """
        pass