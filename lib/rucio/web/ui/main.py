#!/usr/bin/env python
"""
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Thomas Beermann, <thomas.beermann@cern.ch>, 2014-2017
 - Mario Lassnig, <mario.lassnig@cern.ch>, 2014-2015
 - Martin Barisits, <martin.barisits@cern.ch>, 2014
 - Ralph Vigne <ralph.vigne@cern.ch>, 2015
 - Cedric Serfon <cedric.serfon@cern.ch>, 2015-2017
"""


from os.path import dirname, join

from web import application, header, input as param_input, seeother, template

from rucio.common.utils import generate_http_error
from rucio.web.ui.common.utils import check_token, get_token


URLS = (
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
    '/lifetime_exception', 'LifetimeException',
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
    '/subscriptions_editor', 'SubscriptionsEditor',

)


class AccountUsage(object):
    """ Group Account Usage overview """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.account_usage())


class AccountRSEUsage(object):
    """ RSE usage per account  """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.account_rse_usage())


class ApproveRules(object):
    """ R2D2 rule approval overview """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.approve_rules())


class Auth(object):
    """ Local Auth Proxy """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        token = get_token()
        if token:
            header('X-Rucio-Auth-Token', token)
            return str()
        else:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot get token')


class Accounting(object):
    """ Accounting """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.accounting())


class BadReplicas(object):
    """ Bad replica monitoring """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.bad_replicas())


class SuspiciousReplicas(object):
    """ AccountUsage """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.suspicious_replicas())


class BadReplicasSummary(object):
    """ Bad replica overview """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.bad_replicas_summary())


class BacklogMon(object):
    """ Rule Backlog Monitor """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.backlog_mon())


class Cond(object):
    """ Condition DB overview """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.cond())


class DID(object):
    """ DID detail page """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.did())


class DBRelease(object):
    """ DB release overview """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.dbrelease())


class Dumps(object):
    """ Description page for dumps """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.dumps())


class Heartbeats(object):
    """ Heartbeat monitoring """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.heartbeats())


class LifetimeException():
    """ For to request lifetime exception """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.lifetime_exception())


class ListRules(object):
    """ R2D2 rules list """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.list_rules())


class ListRulesRedirect(object):
    """ R2D2 redirect from old url """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        params = param_input()
        url = '/r2d2?'
        for key, value in params.items():
            url += key + '=' + value + '&'
        seeother(url[:-1])


class Rule(object):
    """ Rule details page """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.rule())


class RequestRule(object):
    """ R2D2 request page """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.request_rule())


class RequestRuleRedirect(object):
    """ R2D2 redirect from old url """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        seeother('/r2d2/request')


class Subscription(object):
    """ Subscription detail page """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.subscription())


class SubscriptionRules(object):
    """ Rule list for a subscription """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.subscriptionrules())


class Index(object):
    """ Main page """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.index())


class Infrastructure(object):
    """ Infrastructure overview """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.infrastructure())


class Rules(object):
    """ Rules list """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.rules())


class RSEUsage(object):
    """ Disk space usage per RSE """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.rse_usage())


class RSEAccountUsage(object):
    """ RSE account usage """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.rse_account_usage())


class RSELocks(object):
    """ Locks overview per RSE """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.rse_locks())


class Search(object):
    """ Search page for dids """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.search())


class Subscriptions(object):
    """ Subscriptions overview """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.subscriptions())


class SubscriptionsEditor():
    """ Subscriptions editor """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.subscriptions_editor())


"""----------------------
   Web service startup
----------------------"""

app = application(URLS, globals())
application = app.wsgifunc()
