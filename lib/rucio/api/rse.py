# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012


def add_rse(RSEName):
        """
        Creates a new Rucio Storage Element (RSE).

        :param RSEName: The rse name.

        :returns: If the operation is successful a response code of "0" is returned. If an error occurs, a non zero response code is returned.
        """
        rse.add_rse(RSEName)


def add_rse_tag(rse, tag, scope=None):
        """
        Tags a rse.

        :param rse:   The rse name.
        :param tag:   The tag.
        :param scope: The tag name-space, e.g., site, federation, tier.

        :returns: If the operation is successful a response code of "0" is returned. If an error occurs, a non zero response code is returned.
        """
        pass


def list_rses(**kwargs):
        """
        Returns a list of rse/tag mappings

        :param filters: dictionary of attributes by which the resulting
                        collection of rses should be filtered
        :param limit: maximum number of items to return
        :param sort_key: results will be ordered by this rse attribute
        :param sort_dir: direction in which to to order results (asc, desc)

        :returns: If the operation is successful a response code of "0" is returned. If an error occurs, a non zero response code is returned.
        """
        pass
