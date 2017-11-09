# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Joaquin Bogado, <jbogadog@cern.ch>, 2017

"""
Forecast library to predict the Transfers Time To Complete (T3C)
"""

import json
import numpy as np
import requests
import time


class T3CModel():
    def __init__(self, path=''):
        try:
            self.model = json.load(open(path, 'r'))
        except IOError:
            self.model = {"STANDARD_LINK": {"r2": 0.0,
                                            "rmse": 0.0,
                                            "rate": 23399639.38262837,
                                            "datalen": 0.0,
                                            "overhead": 12.025538382153206,
                                            "diskrw": 12046990.897099394}}

        # Create RSE to site name dictionary
        r = requests.get('http://atlas-agis-api.cern.ch/\
request/site/query/list/ddmendpoints?json')
        j = r.json()
        self._rse2site = {}
        self._site2rses = {}
        for i in j:
            self._site2rses[i['name']] = i['ddmendpoints'].keys()
            for ep in i['ddmendpoints']:
                self._rse2site[ep] = i['name']

    def ewma(self, x, span):
        N = x.size
        alpha = 2.0 / (1 + span)
        s = np.zeros((N,))
        s[0] = x[0]
        for i in range(1, N):
            s[i] = alpha * x[i] + (1 - alpha) * (s[i - 1])
        return s

    # Site to RSE and RSE to site conversions
    def rse2site(self, rse):
        try:
            return self._rse2site[rse]
        except KeyError:
            return ''

    def site2rses(self, site):
        try:
            return self._site2rses[site]
        except KeyError:
            return []

    # Net time prediction
    def recover_params(self, link):
        try:
            values = self.model[link]
        except KeyError:
            link = 'STANDARD_LINK'
            values = self.model['STANDARD_LINK']
        return link, values['rate'], values['overhead'], values['diskrw']

    def predict_n(self, link, size):
        link_true, rate, overhead, diskrw = self.recover_params(link)
        if 'STANDARD_LINK' == link_true:
            print 'W: Link', link, 'not found, using standard parameters...'
        else:
            print 'I: Using', link, 'data from model to predict.'
        rate_pred = min((size / (size / rate) + overhead), diskrw)
        return size / rate_pred

    # Queue time prediction
    def get_submitted_at_to_rucio(self, src, dst, act):
        return None

    def get_submitted_at_random(self, src, dst, act):
        submitted = [np.random.randint(time.time() - 7 * 24 * 60 * 60,
                     time.time()) for i in xrange(150)]
        return submitted

    def predict_q(self, link):
        src, dst, act = link.split('__')
        submitted = self.get_submitted_at_random(src, dst, act)
        submitted = np.array(submitted)
        submitted = int(time.time()) - submitted
        return self.ewma(submitted, span=10)[-1]

    # Overall prediction
    def predict(self, transfers):
        result = []
        for t in transfers:
            src = self.rse2site(t['src'])
            dst = self.rse2site(t['dst'])
            act = t['activity']
            size = t['size']
            link_n = '__'.join([src, dst])
            link_q = '__'.join([src, dst, act])
            t['ntime'] = self.predict_n(link_n, size)
            t['qtime'] = self.predict_q(link_q)
            result.append(t)
        return result
