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

import base64
import datetime
import hmac
import time
from hashlib import sha1
from urllib.parse import urlparse, urlencode

import boto3
from botocore.client import Config
from dogpile.cache.api import NO_VALUE
from google.oauth2.service_account import Credentials

from rucio.common.cache import make_region_memcached
from rucio.common.config import config_get, get_rse_credentials
from rucio.common.exception import UnsupportedOperation
from rucio.core.monitor import MetricManager
from rucio.core.rse import get_rse_attribute

CREDS_GCS = None

REGION = make_region_memcached(expiration_time=900)
METRICS = MetricManager(module=__name__)


def get_signed_url(rse_id: str, service: str, operation: str, url: str, lifetime=600) -> str:
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
        if not isinstance(lifetime, int):
            try:
                lifetime = int(lifetime)
            except:
                raise UnsupportedOperation('Lifetime must be convertible to numeric.')

    if service == 'gcs':
        if not CREDS_GCS:
            CREDS_GCS = Credentials.from_service_account_file(config_get('credentials', 'gcs',
                                                                         raise_exception=False,
                                                                         default='/opt/rucio/etc/google-cloud-storage-test.json'))
        components = urlparse(url)
        host = components.netloc

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
        path = components.path

        # assemble message to sign
        to_sign = "%s\n\n\n%s\n%s" % (operation, lifetime, path)

        # create URL-capable signature
        # first character is always a '=', remove it
        signature = urlencode({'': base64.b64encode(CREDS_GCS.sign_bytes(to_sign))})[1:]

        # assemble final signed URL
        signed_url = (
            f'https://{host}{path}'
            f'?GoogleAccessId={CREDS_GCS.service_account_email}'
            f'&Expires={lifetime}&Signature={signature}'
        )

    elif service == 's3':

        # get RSE S3 URL style (path or host)
        # path-style: https://s3.region-code.amazonaws.com/bucket-name/key-name
        # host-style: https://bucket-name.s3.region-code.amazonaws.com/key-name
        s3_url_style = get_rse_attribute(rse_id, 's3_url_style')

        # no S3 URL style specified, assume path-style
        if s3_url_style is None:
            s3_url_style = "path"

        # split URL to get hostname, bucket and key
        components = urlparse(url)
        host = components.netloc
        pathcomponents = components.path.split('/')
        if s3_url_style == "path":
            if len(pathcomponents) < 3:
                raise UnsupportedOperation('Not a valid Path-Style S3 URL')
            bucket = pathcomponents[1]
            key = '/'.join(pathcomponents[2:])
        elif s3_url_style == "host":
            hostcomponents = host.split('.')
            bucket = hostcomponents[0]
            if len(pathcomponents) < 2:
                raise UnsupportedOperation('Not a valid Host-Style S3 URL')
            key = '/'.join(pathcomponents[1:])
        else:
            raise UnsupportedOperation('Not a valid RSE S3 URL style (allowed values: path|host)')

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

        with METRICS.timer('signs3'):

            if s3_url_style == "host":
                s3_url_style = "virtual"

            s3 = boto3.client(service_name='s3',
                              endpoint_url=f'https://{host}:{port}',
                              aws_access_key_id=access_key,
                              aws_secret_access_key=secret_key,
                              config=Config(signature_version=signature_version,
                                            region_name=region_name,
                                            s3={"addressing_style": s3_url_style}))

            signed_url: str = s3.generate_presigned_url(
                s3op, Params={'Bucket': bucket, 'Key': key}, ExpiresIn=lifetime)

    else:  # service == 'swift'
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
        with METRICS.timer('signswift'):
            hmac_body = '%s\n%s\n%s' % (swiftop, expires, components.path)
            # Python 3 hmac only accepts bytes or bytearray
            sig = hmac.new(bytearray(tempurl_key, 'utf-8'), bytearray(hmac_body, 'utf-8'), sha1).hexdigest()
            signed_url = f'https://{host}{components.path}?temp_url_sig={sig}&temp_url_expires={expires}'

    return signed_url
