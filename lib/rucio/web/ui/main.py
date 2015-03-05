#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2014-2015
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
# - Martin Barisits, <martin.barisits@cern.ch>, 2014
# - Ralph Vigne <ralph.vigne@cern.ch>, 2015
# - Cedric Serfon <cedric.serfon@cern.ch>, 2015

from os.path import dirname, join

from web import application, header, template

from rucio.common.utils import generate_http_error
from rucio.web.ui.common.utils import check_token, get_token


urls = (
    '/', 'Index',
    '/account_usage', 'AccountUsage',
    '/auth', 'Auth',
    '/accounting', 'Accounting',
    '/bad_replicas', 'BadReplicas',
    '/did', 'DID',
    '/dumps', 'Dumps',
    '/infrastructure', 'Infrastructure',
    '/list_rules', 'ListRules',
    '/rse_usage', 'RSEUsage',
    '/rse_locks', 'RSELocks',
    '/rule', 'Rule',
    '/rules', 'Rules',
    '/rule_backlog_monitor', 'BacklogMon',
    '/search', 'Search',
    '/subscriptions/rules', 'SubscriptionRules',
    '/subscription', 'Subscription',
    '/subscriptions', 'Subscriptions',
    '/webstats/accounts', 'HTTPMonitoringAccounts',
    '/webstats/resources', 'HTTPMonitoringResources',
    '/webstats/accounts/(.*)', 'HTTPMonitoringAccountDetails',
)


class AccountUsage():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.account_usage())


class Auth():
    def GET(self):
        token = get_token()
        if token:
            header('X-Rucio-Auth-Token', token)
            return str()
        else:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot get token')


class Accounting():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.accounting())


class BadReplicas():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.bad_replicas())


class BacklogMon():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.backlog_mon())


class DID():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.did())


class Dumps():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.dumps())


class ListRules():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.list_rules())


class Rule():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.rule())


class Subscription():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.subscription())


class SubscriptionRules():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.subscriptionrules())


class Index():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.index())


class Infrastructure():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.infrastructure())


class Rules():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.rules())


class RSEUsage():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.rse_usage())


class RSELocks():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.rse_locks())


class Search():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.search())


class Subscriptions():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.subscriptions())


class HTTPMonitoringAccounts():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return render.base("", "", "", render.http_monitoring_accounts())


class HTTPMonitoringResources():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return render.base("", "", "", render.http_monitoring_resources())


class HTTPMonitoringAccountDetails():
    def GET(self, account):
        render = template.render(join(dirname(__file__), 'templates/'))
        return render.base("", "", "", render.http_monitoring_account_details())


"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
application = app.wsgifunc()
