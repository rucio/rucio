#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2014
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
# - Martin Barisits, <martin.barisits@cern.ch>, 2014

from os.path import dirname, join

from web import application, template

from rucio.web.ui.common.utils import check_token


urls = (
    '/', 'Index',
    '/search', 'Search',
    '/accounting', 'Accounting',
    '/subscriptions', 'Subscriptions',
    '/infrastructure', 'Infrastructure',
    '/rules', 'Rules'
    )


class Index():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.index())


class Search():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.search())


class Accounting():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.accounting())


class Subscriptions():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.subscriptions())


class Infrastructure():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.infrastructure())


class Rules():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.rules())


"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
application = app.wsgifunc()
