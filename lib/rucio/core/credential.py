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

import base64
import datetime
import time
import urllib
import urlparse

from rucio.common.config import config_get
from rucio.common.exception import UnsupportedOperation

from oauth2client.service_account import ServiceAccountCredentials


CREDS_GCS = ServiceAccountCredentials.from_json_keyfile_name(config_get('credentials', 'gcs'))


def get_signed_url(service, operation, url, lifetime=600):
    """
    Get a signed URL for a particular service and operation.

    The signed URL will be valid for 1 hour.

    :param service: The service to authorise, currently only 'gsc'.
    :param operation: The operation to sign, either 'read', 'write', or 'delete'.
    :param url: The URL to sign.
    :param lifetime: Lifetime of the signed URL in seconds.
    :returns: Signed URL as a variable-length string.
    """

    if service not in ['gcs']:
        raise UnsupportedOperation('Service must be "gcs"')

    if operation not in ['read', 'write', 'delete']:
        raise UnsupportedOperation('Operation must be "read", "write", or "delete"')

    if url is None or url == '':
        raise UnsupportedOperation('URL must not be empty')

    if not isinstance(lifetime, (int, long)) and lifetime > 0:
        raise UnsupportedOperation('Lifetime must be greater than 0.')

    signed_url = None
    if service == 'gcs':

        # select the correct operation
        operations = {'read': 'GET', 'write': 'PUT', 'delete': 'DELETE'}
        operation = operations[operation]

        # special case to test signature, force epoch time
        if lifetime is None:
            lifetime = 0
        else:
            # GCS is timezone-sensitive, don't use UTC
            # has to be converted to Unixtime
            lifetime = datetime.datetime.now() + datetime.timedelta(seconds=lifetime)
            lifetime = int(time.mktime(lifetime.timetuple()))

        # sign the path only
        path = urlparse.urlparse(url).path

        # assemble message to sign
        to_sign = "%s\n\n\n%s\n%s" % (operation, lifetime, path)

        # create URL-capable signature
        # first character is always a '=', remove it
        signature = urllib.urlencode({'': base64.b64encode(CREDS_GCS.sign_blob(to_sign)[1])})[1:]

        # assemble final signed URL
        signed_url = 'https://storage.googleapis.com%s?GoogleAccessId=%s&Expires=%s&Signature=%s' % (path,
                                                                                                     CREDS_GCS.service_account_email,
                                                                                                     lifetime,
                                                                                                     signature)

    return signed_url
