# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014

from django.http import response
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
    js_token = None
    js_account = 'root'
    rucio_ui_version = version.version_string()

    if request.is_secure():

        renv = request.environ
        session_token = authentication.validate_auth_token(request.COOKIES.get('x-rucio-auth-token'))

        if session_token is None:
            try:
                token = authentication.get_auth_token_x509('root',
                                                           renv['SSL_CLIENT_S_DN'],
                                                           'webui',
                                                           renv['REMOTE_ADDR'])
            except:
                return render_to_response('problem.html', locals())

            #response.set_cookie('x-rucio-auth-token', value=token, max_age=3600)
            js_token = __to_js('token', token)
        else:
            js_token = __to_js('token', session_token)

    else:
        return render_to_response('problem.html', locals())

    return render_to_response('index.html', locals())
