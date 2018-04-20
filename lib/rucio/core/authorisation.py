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


CREDS_GCS = ServiceAccountCredentials.from_json_keyfile_name(config_get('authorisation', 'creds_gcs'))


def get_signed_url(service, operation, url, expires_at=None):
    """
    Get a signed URL for a particular service and operation.

    The signed URL will be valid for 1 hour.

    :param service: The service to authorise, currently only 'gsc'.
    :param operation: The operation to sign, either 'read', 'write', or 'delete'.
    :param url: The URL to sign.
    :param expires_at: Set expiration timestamp as Unixtime.
    :returns: Signed URL as a variable-length string.
    """

    if service not in ['gcs']:
        raise UnsupportedOperation('Service must be "gcs"')

    if operation not in ['read', 'write', 'delete']:
        raise UnsupportedOperation('Operation must be "read", "write", or "delete"')

    if url is None or url == '':
        raise UnsupportedOperation('URL must not be empty')

    signed_url = None
    if service == 'gcs':

        # select the correct operation
        operations = {'read': 'GET', 'write': 'PUT', 'delete': 'DELETE'}
        operation = operations[operation]

        # default expiration of one hour
        # GCS is timezone-sensitive, don't use UTC
        if expires_at is None:
            expires_at = datetime.datetime.now() + datetime.timedelta(seconds=600)
            expires_at = int(time.mktime(expires_at.timetuple()))

        # sign the path only
        path = urlparse.urlparse(url).path

        # assemble message to sign
        to_sign = "%s\n\n\n%s\n%s" % (operation, expires_at, path)

        # create URL-capable signature
        # first character is always a '=', remove it
        signature = urllib.urlencode({'': base64.b64encode(CREDS_GCS.sign_blob(to_sign)[1])})[1:]

        # assemble final signed URL
        signed_url = 'https://storage.googleapis.com%s?GoogleAccessId=%s&Expires=%s&Signature=%s' % (path,
                                                                                                     CREDS_GCS.service_account_email,
                                                                                                     expires_at,
                                                                                                     signature)

    return signed_url
