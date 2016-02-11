# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Wen Guan, <wen.guan@cern.ch>, 2016
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2016

"""
methods of objectstore
"""

import boto
import boto.s3.connection
import logging
import traceback
import urlparse

from dogpile.cache import make_region
from dogpile.cache.api import NoValue

from rucio.common import config
from rucio.common import exception

logging.getLogger("boto").setLevel(logging.WARNING)
logging.getLogger("boto.s3.connection").setLevel(logging.WARNING)

REGION = make_region().configure('dogpile.cache.memcached',
                                 expiration_time=3600,
                                 arguments={'url': "127.0.0.1:11211", 'distributed_lock': True})

# for local test
REGION = make_region().configure('dogpile.cache.memory',
                                 expiration_time=3600)


def _get_credentials(rse, endpoint):
    """
    Pass an endpoint and return its credentials.

    :param endpoint:      URL endpoint string.
    :param rse:           RSE name.
    :returns:             Dictionary of credentials.
    """

    key = '%s_%s' % (rse, endpoint)
    result = REGION.get(key)
    if type(result) is NoValue:
        try:
            logging.debug("Loading account credentials")
            result = config.get_rse_credentials(None)
            if result and rse in result:
                result = result[rse]
                result['is_secure'] = result['is_secure'][endpoint]
                REGION.set(key, result)
            else:
                raise Exception("Failed to load account credentials")
            logging.debug("Loaded account credentials")
        except KeyError, e:
            raise exception.CannotAuthenticate('RSE %s endpoint %s not in rse account cfg: %s' % (rse, endpoint, e))
        except:
            raise exception.RucioException("Failed to load credentials for RSE(%s) endpoint(%s), error: %s" % (rse, endpoint, traceback.format_exc()))
    return result


def _get_connection(rse, endpoint):
    """
    Pass an endpoint and return a connection to object store.

    :param rse:           RSE name.
    :param endpoint:      URL endpoint string.
    :returns:             Connection object.
    """

    key = "connection:%s_%s" % (rse, endpoint)
    result = REGION.get(key)
    if type(result) is NoValue:
        try:
            logging.debug("Creating connection object")
            result = None
            credentials = _get_credentials(rse, endpoint)
            if 'access_key' in credentials and credentials['access_key'] and \
               'secret_key' in credentials and credentials['secret_key'] and \
               'is_secure' in credentials and credentials['is_secure'] is not None:

                parsed = urlparse.urlparse(endpoint)
                hostname = parsed.netloc.partition(':')[0]
                port = parsed.netloc.partition(':')[2]

                result = boto.connect_s3(aws_access_key_id=credentials['access_key'],
                                         aws_secret_access_key=credentials['secret_key'],
                                         host=hostname,
                                         port=int(port),
                                         is_secure=credentials['is_secure'],
                                         calling_format=boto.s3.connection.OrdinaryCallingFormat())

                REGION.set(key, result)
                logging.debug("Created connection object")
            else:
                raise exception.CannotAuthenticate("Either access_key, secret_key or is_secure is not defined for RSE %s endpoint %s" % (rse, endpoint))
        except exception.RucioException, e:
            raise e
        except:
            raise exception.RucioException("Failed to get connection for RSE(%s) endpoint(%s), error: %s" % (rse, endpoint, traceback.format_exc()))
    return result


def _get_bucket(rse, endpoint, bucket_name):
    """
    Pass an endpoint and return a connection to object store.

    :param rse:           RSE name.
    :param endpoint:      URL endpoint string.
    :returns:             Connection object.
    """

    key = "%s:%s:%s" % (rse, endpoint, bucket_name)
    result = REGION.get(key)
    if type(result) is NoValue:
        try:
            logging.debug("Creating bucket object")
            result = None

            conn = _get_connection(rse, endpoint)
            bucket = conn.get_bucket(bucket_name)
            if bucket is None:
                raise exception.SourceNotFound('Bucket %s not found on %s' % (bucket_name, rse))
            else:
                result = bucket
                REGION.set(key, result)
        except exception.RucioException, e:
            raise e
        except:
            raise exception.RucioException("Failed to get bucket on RSE(%s), error: %s" % (rse, traceback.format_exc()))
    return result


def _get_endpoint_bucket_key(url):
    """
    Parse URL.

    :param url:           URL string.
    :returns:             endpoint, bucket, key.
    """
    try:
        parsed = urlparse.urlparse(url)
        scheme = parsed.scheme
        hostname = parsed.netloc.partition(':')[0]
        port = parsed.netloc.partition(':')[2]
        endpoint = ''.join([scheme, '://', hostname, ':', port])
        while '//' in parsed.path:
            parsed = parsed._replace(path=parsed.path.replace('//', '/'))
        path = parsed.path
        if path.startswith('/'):
            path = path[1:]
        bucket_name = path.split('/')[0]
        key_name = path.replace(bucket_name + '/', '')
        return endpoint, bucket_name, key_name
    except:
        raise exception.RucioException("Failed to parse url %s, error: %s" % (url, traceback.format_exc()))


def connect(rse, url):
    """
    connect to RSE.

    :param url:           URL string.
    :param rse:           RSE name.
    """
    try:
        endpoint, bucket_name, key_name = _get_endpoint_bucket_key(url)
        conn = _get_connection(rse, endpoint)
        conn.create_bucket(bucket_name)
    except:
        raise exception.RucioException("Failed to connect url %s, error: %s" % (url, traceback.format_exc()))


def get_signed_urls(urls, rse, operation='read'):
    """
    Pass list of urls and return their signed urls.

    :param urls:          A list of URL string.
    :param rse:           RSE name.
    :returns:             Dictionary of Signed URLs.
    """
    result = {}
    for url in urls:
        try:
            endpoint, bucket_name, key_name = _get_endpoint_bucket_key(url)

            signed_url = None
            if operation == 'read':
                # signed_url = conn.generate_url(3600, 'GET', bucket_name, key_name, query_auth=True, force_http=False)
                bucket = _get_bucket(rse, endpoint, bucket_name)
                key = bucket.get_key(key_name)
                if key is None:
                    signed_url = exception.SourceNotFound('Key %s not found on %s' % (key_name, endpoint))
                else:
                    signed_url = key.generate_url(3600, 'GET', query_auth=True, force_http=False)
            else:
                conn = _get_connection(rse, endpoint)
                signed_url = conn.generate_url(3600, 'PUT', bucket_name, key_name, query_auth=True, force_http=False)
            result[url] = signed_url
        except boto.exception.S3ResponseError as e:
            if e.status in [404, 403]:
                result[url] = exception.DestinationNotAccessible(e)
            else:
                result[url] = exception.ServiceUnavailable(e)
        except exception.RucioException, e:
            result[url] = e
        except:
            result[url] = exception.RucioException("Failed to get signed url for %s, error: %s" % (url, traceback.format_exc()))
    return result


def get_metadata(urls, rse):
    """
    Pass list of urls and return their metadata.

    :param urls:          A list of URL string.
    :param rse:           RSE name.
    :returns:             Dictonary of metadatas.
    """
    result = {}
    for url in urls:
        try:
            endpoint, bucket_name, key_name = _get_endpoint_bucket_key(url)
            bucket = _get_bucket(rse, endpoint, bucket_name)
            metadata = None
            key = bucket.get_key(key_name)
            if key is None:
                metadata = exception.SourceNotFound('Key %s not found on %s' % (key_name, endpoint))
            else:
                metadata = {'filesize': key.size}
            result[url] = metadata
        except boto.exception.S3ResponseError as e:
            if e.status in [404, 403]:
                raise exception.DestinationNotAccessible(e)
            else:
                raise exception.ServiceUnavailable(e)
        except exception.RucioException, e:
            result[url] = e
        except:
            result[url] = exception.RucioException("Failed to get metadata for %s, error: %s" % (endpoint, traceback.format_exc()))
    return result


def _delete_keys(bucket, keys):
    """
    Delete objects in the same bucket.

    :param bucket:        Bucket object.
    :param keys:          List of keys.
    :returns:             Dictonary of {'status': status, 'output': output}.
    """
    result = {}
    status = -1
    output = None
    try:
        deleted_result = bucket.delete_keys(keys)
        for deleted in deleted_result.deleted:
            result[deleted.key] = {'status': 0, 'output': None}
        for error in deleted_result.errors:
            result[error.key] = {'status': -1, 'output': error.message}
    except:
        status = -1
        output = "Failed to delete keys, error: %s" % (traceback.format_exc())

    for key in keys:
        if key not in result:
            result[key] = {'status': status, 'output': output}
    return result


def delete(urls, rse):
    """
    Delete objects.

    :param urls:          A list of URL string.
    :param rse:           RSE name.
    :returns:             Dictonary of {'status': status, 'output': output}.
    """
    result = {}
    bucket_keys = {}
    for url in urls:
        try:
            endpoint, bucket_name, key_name = _get_endpoint_bucket_key(url)
            bucket_key = '%s+%s' % (endpoint, bucket_name)
            if bucket_key not in bucket_keys:
                bucket_keys[bucket_key] = {}
            bucket_keys[bucket_key][key_name] = url
        except:
            result[url] = {'status': -1, 'output': "Failed to delete url: %s, error: %s" % (url, traceback.format_exc())}

    for bucket_key in bucket_keys:
        try:
            endpoint, bucket_name = bucket_key.split('+')
            bucket = _get_bucket(rse, endpoint, bucket_name)
            ret = _delete_keys(bucket, bucket_keys[bucket_key].keys())
            for key in ret:
                result[bucket_keys[bucket_key][key]] = ret[key]
        except:
            ret = {'status': -1, 'output': "Failed to delete url: %s, error: %s" % (url, traceback.format_exc())}
            for key in bucket_keys[bucket_key].keys():
                url = bucket_keys[bucket_key][key]
                if url not in result:
                    result[url] = ret

    return result


def delete_dir(url_prefix, rse):
    """
    Delete objects starting with prefix.

    :param url_prefix:          URL string.
    :param rse:           RSE name.
    :returns                    {'status': status, 'output': output}
    """
    try:
        endpoint, bucket_name, key_name = _get_endpoint_bucket_key(url_prefix)
        bucket = _get_bucket(rse, endpoint, bucket_name)
        i = 0
        keys = []
        for key in bucket.list(prefix=key_name):
            keys.append(key.name)
            i += 1
            if i == 1000:
                ret = _delete_keys(bucket, keys)
                for ret_key in ret:
                    if ret[ret_key]['status'] != 0:
                        return ret[ret_key]['status'], ret[ret_key]['output']
                i = 0
                keys = []
        if len(keys):
            ret = _delete_keys(bucket, keys)
            for ret_key in ret:
                if ret[ret_key]['status'] != 0:
                    return ret[ret_key]['status'], ret[ret_key]['output']
        return 0, None
    except:
        return -1, "Failed to delete dir: %s, error: %s" % (url_prefix, traceback.format_exc())


def rename(url, new_url, rse):
    """
    Rename object.

    :param url:          URL string.
    :param new_url:      URL string.
    :param rse:           RSE name.
    """
    try:
        endpoint, bucket_name, key_name = _get_endpoint_bucket_key(url)
        bucket = _get_bucket(rse, endpoint, bucket_name)
        key = bucket.get_key(key_name)
        if key is None:
            raise exception.SourceNotFound('Key %s not found on %s' % (key_name, endpoint))

        new_endpoint, new_bucket_name, new_key_name = _get_endpoint_bucket_key(new_url)
        if endpoint != new_endpoint:
            raise exception.RucioException("New endpont %s is different with old endpoint %s, cannot rename to different OS" % (new_endpoint, endpoint))

        key.copy(new_bucket_name, new_key_name)
        key.delete()
    except boto.exception.S3ResponseError as e:
        if e.status in [404, 403]:
            raise exception.DestinationNotAccessible(e)
        else:
            raise exception.ServiceUnavailable(e)
    except exception.RucioException, e:
        raise e
    except:
        raise exception.RucioException("Failed to get metadata for %s, error: %s" % (endpoint, traceback.format_exc()))
