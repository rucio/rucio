# Copyright 2012-2018 CERN for the benefit of the ATLAS collaboration.
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
#
# Authors:
# - Mario Lassnig <mario@lassnig.net>, 2018
#
# PY3K COMPATIBLE

from rucio.api import permission
from rucio.common import exception
from rucio.core import credential


def get_signed_url(account, appid, ip, service, operation, url, lifetime):
    """
    Get a signed URL for a particular service and operation.

    The signed URL will be valid for 1 hour.

    :param account: Account identifier as a string.
    :param appid: The application identifier as a string.
    :param ip: IP address of the client as a string.
    :param service: The service to authorise, currently only 'gsc'.
    :param operation: The operation to sign, either 'read', 'write', or 'delete'.
    :param url: The URL to sign.
    :param lifetime: Lifetime in seconds.
    :returns: Signed URL as a variable-length string.
    """

    kwargs = {'account': account}
    if not permission.has_permission(issuer=account, action='get_signed_url', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not get signed URL for service=%s, operation=%s, url=%s, lifetime=%s' % (account,
                                                                                                                              service,
                                                                                                                              operation,
                                                                                                                              url,
                                                                                                                              lifetime))

    return credential.get_signed_url(service, operation, url, lifetime)
