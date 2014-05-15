# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014

from django.shortcuts import render_to_response

from rucio import version
from rucio.api import authentication


def __to_js(var, value):
    """
    Encapsulates django variable into a javascript var.

    :param var: The name of the javascript var.
    :param value: The value to set.
    """

    return '<script type="text/javascript">var %s = "%s";</script>' % (var, value)


def index(request):
    """ index.html """

    token = None
    rucio_monitor_version = version.version_string()
    rucio_account = 'root'

    if request.is_secure():
        renv = request.environ
        token = authentication.get_auth_token_x509(rucio_account,
                                                   renv['SSL_CLIENT_S_DN'],
                                                   'ruciomon',
                                                   renv['REMOTE_ADDR'])
        js_token = __to_js('token', token)

    return render_to_response('index.html', locals())
