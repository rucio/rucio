# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2013
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
#
# PY3K COMPATIBLE

from logging import getLogger, Formatter, DEBUG
from logging.config import fileConfig
from logging.handlers import RotatingFileHandler
from time import time
import os

from json import dumps
from uuid import uuid4 as uuid
from web import ctx
from rucio.common.config import get_config_dirs

# try to configure the logger from the config file. Otherwise fall back to default values.

configfiles = (os.path.join(confdir, 'web', 'logging.conf') for confdir in get_config_dirs())
configfiles = list(filter(os.path.exists, configfiles))

if len(configfiles) != 0:
    fileConfig(configfiles[0])
    logger = getLogger('rucio')
else:
    logger = getLogger('rucio')
    logger.setLevel(DEBUG)

    rfh = RotatingFileHandler('/var/log/rucio/access.log', 'a', 1000000000, 2)
    rfh.setLevel(DEBUG)

    FORMAT = '%(asctime)s\t%(levelname)s\t%(ip)s\t%(duration)s\t%(account)s\t%(appid)s\t%(clientref)s\t%(uri)s\t%(requestid)s\t%(requestHeader)s\t%(responseHeader)s\t%(httpCode)s'
    formatter = Formatter(FORMAT)
    rfh.setFormatter(formatter)

    logger.addHandler(rfh)


def log(fn):
    """
    logging decorator for the for the REST method calls. Gets all important information
    about the request and response, takes the time to complete the calls and writes it
    to the logs.
    """
    def wrapped(self, *args):
        try:
            start = time()
            ret = fn(self, *args)
            duration = time() - start
            logData = extractLogData(ctx)
            logData['duration'] = duration
            logData['httpCode'] = ctx.status
            logData['responseHeader'] = dumps(ctx.headers)
            logger.info('', extra=logData)
            return ret
        except Exception:
            duration = time() - start
            logData = extractLogData(ctx)
            logData['duration'] = duration
            logData['httpCode'] = ctx.status
            logData['responseHeader'] = dumps(ctx.headers)
            if ctx.status[0] == '2':
                logger.info('', extra=logData)
            else:
                logger.error('', extra=logData)
            raise
    return wrapped


def extractLogData(context):
    """
    helper function to extract all important data from the web context.

    :param context: the web.py context object
    :return: a dictionary with all information for the logging.
    """
    logData = {}

    logData['ip'] = context.ip
    logData['account'] = context.env.get('HTTP_RUCIO_ACCOUNT')
    logData['appid'] = 'clients'  # has to changed, but atm no appid is send with the clients
    logData['clientref'] = context.env.get('HTTP_RUCIO_CLIENTREF')
    logData['uri'] = context.method + ' ' + context.protocol + "://" + context.host + context.homepath + context.fullpath
    logData['requestid'] = uuid()
    logData['requestHeader'] = context.env
    logData['responseHeader'] = ''
    logData['httpCode'] = ''
    logData['duration'] = ''
    return logData
