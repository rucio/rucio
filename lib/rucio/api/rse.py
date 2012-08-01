# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

import rucio.api.permission
import rucio.common.exception

from rucio.core import rse as rse_core


def add_rse(rse, issuer):
        """
        Creates a new Rucio Location/RSE.

        :param rse: The rse name.
        :param issuer: The issuer account.

        :returns: If the operation is successful a response code of "0" is returned. If an error occurs, a non zero response code is returned.
        """
        kwargs = {'rse': rse}
        if not rucio.api.permission.has_permission(issuer=issuer, action='add_rse', kwargs=kwargs):
            raise rucio.common.exception.AccessDenied('Account %s can not add RSE' % (issuer))
        return rse_core.add_rse(rse)


def del_rse(rse, issuer):
        """
        Disables a RSE with the provided RSE name.

        :param rse: The rse name.
        :param issuer: The issuer account.
        """
        kwargs = {'rse': rse}
        if not rucio.api.permission.has_permission(issuer=issuer, action='del_rse', kwargs=kwargs):
            raise rucio.common.exception.AccessDenied('Account %s can not delete RSE' % (issuer))

        return rse_core.del_rse(rse)


def list_rses():
        """
        Lists all the rses.


        :returns: List of all RSEs.
        """
        return rse_core.list_rses()
