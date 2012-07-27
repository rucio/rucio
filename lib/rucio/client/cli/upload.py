# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2012


from rucio.client import uploadclient


def upload(sources):
    """ This method just links the CLI upload to the accodring method of the client API."""
    uploadclient.upload(sources)
