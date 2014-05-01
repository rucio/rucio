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


def index(request):
    """
    Renders the index.html template.
    """

    rucio_user = 'Anonymous'
    rucio_version = 'Unknown'

    if request.is_secure():
        renv = request.environ
        rucio_user = renv['SSL_CLIENT_S_DN']

    rucio_version = '%s (%s)' % (version.version_string(),
                                 version.vcs_version_string())

    return render_to_response('index.html', {'rucio_user': rucio_user,
                                             'rucio_version': rucio_version})
