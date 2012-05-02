# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2012

import pprint

from rucio.common import exception


class RSEException(exception.RucioException):

    def __init__(self, error_id, error_message, **error_data):
        self.error_id = error_id
        self.error_message = error_message
        self.error_data = error_data

    def __str__(self):
        s = 'ERROR No. ' + str(self.error_id) + ' => ' + self.error_message + '\n'
        s += pprint.PrettyPrinter(indent=4).pformat(self.error_data) + '\n'
        return s
