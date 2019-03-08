#!/usr/bin/env python
# Copyright 2014-2018 CERN for the benefit of the ATLAS collaboration.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors:
# - Thomas Beermann <thomas.beermann@cern.ch>, 2014-2017
# - Vincent Garonne <vgaronne@gmail.com>, 2014
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014-2018
# - Martin Barisits <martin.barisits@cern.ch>, 2014-2015
# - Ralph Vigne <ralph.vigne@cern.ch>, 2015
# - Cedric Serfon <cedric.serfon@cern.ch>, 2015-2019
# - Stefan Prenner <stefan.prenner@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
#
# PY3K COMPATIBLE

from io import BytesIO
from json import dumps
from os.path import dirname, join
from tarfile import open, TarError

from gzip import GzipFile
from requests import get, ConnectionError
from web import application, header, input as param_input, seeother, template

from rucio.common.config import config_get
from rucio.common.utils import generate_http_error
from rucio.web.ui.common.utils import check_token, get_token


COMMON_URLS = (
    '/account_rse_usage', 'AccountRSEUsage',
    '/account', 'Account',
    '/auth', 'Auth',
    '/bad_replicas', 'BadReplicas',
    '/suspicious_replicas', 'SuspiciousReplicas',
    '/bad_replicas/summary', 'BadReplicasSummary',
    '/did', 'DID',
    '/heartbeats', 'Heartbeats',
    '/lifetime_exception', 'LifetimeException',
    '/list_lifetime_exceptions', 'ListLifetimeExceptions',
    '/list_accounts', 'ListAccounts',
    '/list_rules', 'ListRulesRedirect',
    '/r2d2/approve', 'ApproveRules',
    '/r2d2/request', 'RequestRule',
    '/r2d2/manage_quota', 'RSEAccountUsage',
    '/r2d2', 'ListRules',
    '/rse', 'RSE',
    '/rse/protocol/add', 'AddRSEProtocol',
    '/rses', 'RSES',
    '/rses/add', 'AddRSE',
    '/rse_usage', 'RSEUsage',
    '/rse_locks', 'RSELocks',
    '/rule', 'Rule',
    '/rules', 'Rules',
    '/request_rule', 'RequestRuleRedirect',
    '/search', 'Search',
    '/subscriptions/rules', 'SubscriptionRules',
    '/subscription', 'Subscription',
    '/subscriptions', 'Subscriptions',
    '/subscriptions_editor', 'SubscriptionsEditor',
    '/logfiles/load', 'LoadLogfile',
    '/logfiles/extract', 'ExtractLogfile'
)

POLICY = config_get('policy', 'permission')

ATLAS_URLS = ()
OTHER_URLS = ()

if POLICY == 'atlas':
    ATLAS_URLS = (
        '/', 'AtlasIndex',
        '/account_usage', 'AccountUsage',
        '/account_usage_history', 'AccountUsageHistory',
        '/dumps', 'Dumps',
        '/accounting', 'Accounting',
        '/conditions_summary', 'Cond',
        '/dbrelease_summary', 'DBRelease',
        '/infrastructure', 'Infrastructure',
        '/rule_backlog_monitor', 'BacklogMon'
    )
else:
    OTHER_URLS = (
        '/', 'Index'
    )


class Account(object):
    """ Account info page """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.account())


class AccountUsage(object):
    """ Group Account Usage overview """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.account_usage())


class AccountUsageHistory(object):
    """ Group Account Usage overview """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.account_usage_history())


class AccountRSEUsage(object):
    """ RSE usage per account  """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.account_rse_usage())


class AddRSE(object):
    """ Add RSE """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.add_rse())


class AddRSEProtocol(object):
    """ Add protocol to RSE """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.rse_add_protocol())


class ApproveRules(object):
    """ R2D2 rule approval overview """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.approve_rules())


class AtlasIndex(object):
    """ Main page """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.atlas_index())


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


class ListLifetimeExceptions():
    """ List lifetime exceptions requests """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.list_lifetime_exceptions())


class ListAccounts(object):
    """ Account list """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.accounts())


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


class RSE(object):
    """ RSE detail page """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.rse())


class RSES(object):
    """ List of all RSEs """
    def GET(self):  # pylint:disable=no-self-use,invalid-name
        """ GET """
        render = template.render(join(dirname(__file__), 'templates/'))
        return check_token(render.rses())


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


class LoadLogfile():
    """ Loads logfile content list """
    def GET(self):
        try:
            data = param_input()
            response = get(str(data.file_location), cert=config_get('webui', 'usercert'), verify=False)
            if not response.ok:
                response.raise_for_status()
            cont = response.content
            file_like_object = BytesIO(cont)
            tar = open(mode='r:gz', fileobj=file_like_object)
            jsonResponse = {}
            for member in tar.getmembers():
                jsonResponse[member.name] = member.size
            header('Content-Type', 'application/json')
            return dumps(jsonResponse)
        except ConnectionError as err:
            raise generate_http_error(503, str(type(err)), str(err))
        except TarError as err:
            raise generate_http_error(415, str(type(err)), str(err))
        except IOError as err:
            raise generate_http_error(422, str(type(err)), str(err))
        except Exception as err:
            raise generate_http_error(500, str(type(err)), str(err))


class ExtractLogfile():
    """ Extracts selected logfile content """
    def GET(self):
        try:
            pyDict = {}
            data = param_input()
            response = get(str(data.file_location), cert=config_get('webui', 'usercert'), verify=False)
            if not response.ok:
                response.raise_for_status()
            cont = response.content
            file_like_object = BytesIO(cont)
            tar = open(mode='r:gz', fileobj=file_like_object)
            for member in tar.getmembers():
                if member.name == str(data.file_name):
                    try:
                        f = tar.extractfile(member)
                        pyDict['content'] = f.read(16000000)
                        pyDict['size'] = f.tell()
                        jsonResponse = dumps(pyDict)
                        tar.close()
                        return jsonResponse
                    except UnicodeDecodeError:
                        f = tar.extractfile(member)
                        out = GzipFile(fileobj=f)
                        pyDict['content'] = out.read(16000000)
                        pyDict['size'] = out.tell()
                        jsonResponse = dumps(pyDict)
                        tar.close()
                        return jsonResponse
                    return "ok"
        except ConnectionError as err:
            raise generate_http_error(503, str(type(err)), str(err))
        except TarError as err:
            raise generate_http_error(415, str(type(err)), str(err))
        except IOError as err:
            raise generate_http_error(422, str(type(err)), str(err))
        except Exception as err:
            raise generate_http_error(500, str(type(err)), str(err))


"""----------------------
   Web service startup
----------------------"""

app = application(COMMON_URLS + ATLAS_URLS + OTHER_URLS, globals())
application = app.wsgifunc()
