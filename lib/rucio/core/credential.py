# -*- coding: utf-8 -*-
# Copyright 2018-2021 CERN
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018-2020
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - James Perry <j.perry@epcc.ed.ac.uk>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2021

import base64
import datetime
import hmac
import time
from hashlib import sha1

import boto3
from botocore.client import Config
from dogpile.cache import make_region
from dogpile.cache.api import NO_VALUE
from oauth2client.service_account import ServiceAccountCredentials
from six import integer_types
from six.moves.urllib.parse import urlparse, urlencode

from rucio.common.config import config_get, get_rse_credentials
from rucio.common.exception import UnsupportedOperation
from rucio.core.monitor import record_timer_block

CREDS_GCS = None

REGION = make_region().configure('dogpile.cache.memory',
                                 expiration_time=3600)


def get_signed_url(rse_id, service, operation, url, lifetime=600):
    """
    Get a signed URL for a particular service and operation.

    The signed URL will be valid for 1 hour but can be overriden.

    :param rse_id: The ID of the RSE that the URL points to.
    :param service: The service to authorise, either 'gcs', 's3' or 'swift'.
    :param operation: The operation to sign, either 'read', 'write', or 'delete'.
    :param url: The URL to sign.
    :param lifetime: Lifetime of the signed URL in seconds.
    :returns: Signed URL as a variable-length string.
    """

    global CREDS_GCS

    if service not in ['gcs', 's3', 'swift']:
        raise UnsupportedOperation('Service must be "gcs", "s3" or "swift"')

    if operation not in ['read', 'write', 'delete']:
        raise UnsupportedOperation('Operation must be "read", "write", or "delete"')

    if url is None or url == '':
        raise UnsupportedOperation('URL must not be empty')

    if lifetime:
        if not isinstance(lifetime, integer_types):
            try:
                lifetime = int(lifetime)
            except:
                raise UnsupportedOperation('Lifetime must be convertible to numeric.')

    signed_url = None
    if service == 'gcs':
        if not CREDS_GCS:
            CREDS_GCS = ServiceAccountCredentials.from_json_keyfile_name(config_get('credentials', 'gcs',
                                                                                    raise_exception=False,
                                                                                    default='/opt/rucio/etc/google-cloud-storage-test.json'))

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
        path = urlparse(url).path

        # assemble message to sign
        to_sign = "%s\n\n\n%s\n%s" % (operation, lifetime, path)

        # create URL-capable signature
        # first character is always a '=', remove it
        signature = urlencode({'': base64.b64encode(CREDS_GCS.sign_blob(to_sign)[1])})[1:]

        # assemble final signed URL
        signed_url = 'https://storage.googleapis.com:443%s?GoogleAccessId=%s&Expires=%s&Signature=%s' % (path,
                                                                                                         CREDS_GCS.service_account_email,
                                                                                                         lifetime,
                                                                                                         signature)

    elif service == 's3':
        # split URL to get hostname, bucket and key
        components = urlparse(url)
        host = components.netloc
        pathcomponents = components.path.split('/')
        if len(pathcomponents) < 3:
            raise UnsupportedOperation('Not a valid S3 URL')
        bucket = pathcomponents[1]
        key = '/'.join(pathcomponents[2:])

        # remove port number from host if present
        colon = host.find(':')
        port = '443'
        if colon >= 0:
            port = host[colon + 1:]
            host = host[:colon]

        # look up in RSE account configuration by RSE ID
        cred_name = rse_id
        cred = REGION.get('s3-%s' % cred_name)
        if cred is NO_VALUE:
            rse_cred = get_rse_credentials()
            cred = rse_cred.get(cred_name)
            REGION.set('s3-%s' % cred_name, cred)
        access_key = cred['access_key']
        secret_key = cred['secret_key']
        signature_version = cred['signature_version']
        region_name = cred['region']

        if operation == 'read':
            s3op = 'get_object'
        elif operation == 'write':
            s3op = 'put_object'
        else:
            s3op = 'delete_object'

        with record_timer_block('credential.signs3'):
            s3 = boto3.client('s3', endpoint_url='https://' + host + ':' + port, aws_access_key_id=access_key, aws_secret_access_key=secret_key, config=Config(signature_version=signature_version, region_name=region_name))

            signed_url = s3.generate_presigned_url(s3op, Params={'Bucket': bucket, 'Key': key}, ExpiresIn=lifetime)

    elif service == 'swift':
        # split URL to get hostname and path
        components = urlparse(url)
        host = components.netloc

        # remove port number from host if present
        colon = host.find(':')
        if colon >= 0:
            host = host[:colon]

        # use RSE ID to look up key
        cred_name = rse_id

        # look up tempurl signing key
        cred = REGION.get('swift-%s' % cred_name)
        if cred is NO_VALUE:
            rse_cred = get_rse_credentials()
            cred = rse_cred.get(cred_name)
            REGION.set('swift-%s' % cred_name, cred)
        tempurl_key = cred['tempurl_key']

        if operation == 'read':
            swiftop = 'GET'
        elif operation == 'write':
            swiftop = 'PUT'
        else:
            swiftop = 'DELETE'

        expires = int(time.time() + lifetime)

        # create signed URL
        with record_timer_block('credential.signswift'):
            hmac_body = u'%s\n%s\n%s' % (swiftop, expires, components.path)
            # Python 3 hmac only accepts bytes or bytearray
            sig = hmac.new(bytearray(tempurl_key, 'utf-8'), bytearray(hmac_body, 'utf-8'), sha1).hexdigest()
            signed_url = 'https://' + host + components.path + '?temp_url_sig=' + sig + '&temp_url_expires=' + str(expires)

    return signed_url
