# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2014
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2014

from django.shortcuts import render_to_response

from rucio import version
from rucio.web.ui.utils.decorators import check_token


@check_token
def index(request, js_token=None, js_account=None, accounts=None):
    """ index.html """
    rucio_ui_version = version.version_string()

    return render_to_response('index.html', locals())
