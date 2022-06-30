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

import json
import os
import requests

from rucio.common import exception
from rucio.rse.protocols import protocol


class Default(protocol.RSEProtocol):
    """ Implementing access to RSEs using gsiftp."""

    def __init__(self, protocol_attr, rse_settings, logger=None):
        """ Initializes the object with information about the referred RSE.

            :param props: Properties derived from the RSE Repository
        """
        super(Default, self).__init__(protocol_attr, rse_settings, logger=logger)

    def connect(self):
        """
        Establishes the actual connection to the referred RSE.
        If we decide to use gfal, init should be done here.

        :raises RSEAccessDenied
        """
        pass

    def close(self):
        """
        Closes the connection to RSE.
        """
        pass

    def get_space_usage(self):
        """
        Get RSE space usage information.

        :returns: a list with dict containing 'totalsize' and 'unusedsize'

        :raises ServiceUnavailable: if some generic error occured in the library.
        """
        rse_name = self.rse['rse']
        dest = '/tmp/rucio-gsiftp-site-size_' + rse_name
        space_usage_url = ''
        # url of space usage json, woud be nicer to have it in rse_settings
        agis = requests.get('http://atlas-agis-api.cern.ch/request/ddmendpoint/query/list/?json').json()
        agis_token = ''
        for res in agis:
            if rse_name == res['name']:
                agis_token = res['token']
                space_usage_url = res['space_usage_url']

        import gfal2  # pylint: disable=import-error
        gfal2.set_verbose(gfal2.verbose_level.normal)  # pylint: disable=no-member
        try:
            if os.path.exists(dest):
                os.remove(dest)
            ctx = gfal2.creat_context()  # pylint: disable=no-member
            ctx.set_opt_string_list("SRM PLUGIN", "TURL_PROTOCOLS", ["gsiftp", "rfio", "gsidcap", "dcap", "kdcap"])
            params = ctx.transfer_parameters()
            params.timeout = 3600
            ret = ctx.filecopy(params, str(space_usage_url), str('file://' + dest))

            if ret == 0:
                data_file = open(dest)
                data = json.load(data_file)
                data_file.close()
                if agis_token not in list(data.keys()):
                    print('ERROR: space usage json has different token as key')
                else:
                    totalsize = int(data[agis_token]['total_space'])
                    used = int(data[agis_token]['used_space'])
                    unusedsize = totalsize - used
                    return totalsize, unusedsize
        except Exception as error:
            print(error)
            raise exception.ServiceUnavailable(error)
