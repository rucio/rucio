#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2014-2016
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014-2015
# - Martin Barisits, <martin.barisits@cern.ch>, 2014
# - Ralph Vigne <ralph.vigne@cern.ch>, 2015
# - Cedric Serfon <cedric.serfon@cern.ch>, 2015

from os.path import dirname, join

from web import application, header, input, seeother, template

from rucio.common.utils import generate_http_error
from rucio.web.ui.common.utils import check_token, get_token


urls = (
    '/', 'Index',
    '/account_rse_usage', 'AccountRSEUsage',
    '/account_usage', 'AccountUsage',
    '/auth', 'Auth',
    '/accounting', 'Accounting',
    '/bad_replicas', 'BadReplicas',
    '/suspicious_replicas', 'SuspiciousReplicas',
    '/bad_replicas/summary', 'BadReplicasSummary',
    '/conditions_summary', 'Cond',
    '/did', 'DID',
    '/dbrelease_summary', 'DBRelease',
    '/dumps', 'Dumps',
    '/heartbeats', 'Heartbeats',
    '/infrastructure', 'Infrastructure',
    '/list_rules', 'ListRulesRedirect',
    '/r2d2/approve', 'ApproveRules',
    '/r2d2/request', 'RequestRule',
    '/r2d2/manage_quota', 'RSEAccountUsage',
    '/r2d2', 'ListRules',
    '/rse_usage', 'RSEUsage',
    '/rse_locks', 'RSELocks',
    '/rule', 'Rule',
    '/rules', 'Rules',
    '/request_rule', 'RequestRuleRedirect',
    '/rule_backlog_monitor', 'BacklogMon',
    '/search', 'Search',
    '/subscriptions/rules', 'SubscriptionRules',
    '/subscription', 'Subscription',
    '/subscriptions', 'Subscriptions',
    '/api_usage', 'HTTPAPIUsage',
    '/webstats', 'HTTPMonitoringIndex',
    '/webstats/accounts', 'HTTPMonitoringAccounts',
    '/webstats/accounts/(.*)', 'HTTPMonitoringAccountDetails',
    '/webstats/scriptids', 'HTTPMonitoringScriptIDs',
    '/webstats/scriptids/(.*)', 'HTTPMonitoringScriptIDDetails',
    '/webstats/apiclasses', 'HTTPMonitoringApiClasses',
    '/webstats/apiclasses/(.*)', 'HTTPMonitoringApiClassDetails',
    '/webstats/resources', 'HTTPMonitoringResources',
)


class AccountUsage():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.account_usage())


class AccountRSEUsage():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.account_rse_usage())


class ApproveRules():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.approve_rules())


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


class SuspiciousReplicas():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.suspicious_replicas())


class BadReplicasSummary():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.bad_replicas_summary())


class BacklogMon():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.backlog_mon())


class Cond():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.cond())


class DID():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.did())


class DBRelease():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.dbrelease())


class Dumps():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.dumps())


class Heartbeats():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.heartbeats())


class ListRules():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.list_rules())


class ListRulesRedirect():
    def GET(self):
        params = input()
        url = '/r2d2?'
        for key, value in params.items():
            url += key + '=' + value + '&'
        seeother(url[:-1])


class Rule():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.rule())


class RequestRule():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.request_rule())


class RequestRuleRedirect():
    def GET(self):
        seeother('/r2d2/request')


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


class RSEAccountUsage():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.rse_account_usage())


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


class HTTPAPIUsage():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.http_api_usage())


class HTTPMonitoringIndex():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.http_monitoring_index())


class HTTPMonitoringAccounts():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.http_monitoring_accounts())


class HTTPMonitoringAccountDetails():
    def GET(self, account):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.http_monitoring_account_details())


class HTTPMonitoringScriptIDs():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.http_monitoring_scriptids())


class HTTPMonitoringScriptIDDetails():
    def GET(self, account):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.http_monitoring_scriptid_details())


class HTTPMonitoringApiClasses():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.http_monitoring_apiclasses())


class HTTPMonitoringApiClassDetails():
    def GET(self, account):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.http_monitoring_apiclass_details())


class HTTPMonitoringResources():
    def GET(self):
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.http_monitoring_resources())

"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
application = app.wsgifunc()
