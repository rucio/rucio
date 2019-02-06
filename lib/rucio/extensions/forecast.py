# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Joaquin Bogado, <jbogadog@cern.ch>, 2017
# - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2019
#
# PY3K COMPATIBLE

"""
Forecast library to predict the Transfers Time To Complete (T3C)
"""

from __future__ import division

import datetime as dt
import json
import logging
import time
import numpy as np

from rucio.common.exception import RSENotFound
from rucio.core.rse import list_rses, list_rse_attributes, get_rse_name
from rucio.db.sqla.session import read_session
from rucio.db.sqla import models


def ewma(x_values, span):
    """
    Method to calculate the Exponetialy Weighted Moving Average

    :param x_values: numpy array with the values to smooth.
    :param span: size of the window for smoothing.
    :returns: the smoothed x_values.
    """
    x_lenght = x_values.size
    alpha = 2.0 / (1 + span)
    smoothed = np.zeros((x_lenght,))
    smoothed[0] = x_values[0]
    for i in range(1, x_lenght):
        smoothed[i] = alpha * x_values[i] + (1 - alpha) * (smoothed[i - 1])
    return smoothed


class T3CModel():
    """
    Model object to make transfer time predictions.
    """
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
        self._rse2site = {}
        self._rseid2site = {}
        self._site2rses = {}
        self._site2rseids = {}

        for rse in list_rses():
            if rse['deleted'] is False:
                attribs = list_rse_attributes(rse['rse'])
                try:
                    self._rse2site[rse['rse']] = attribs['site']
                    self._rseid2site[rse['id']] = attribs['site']
                except KeyError:
                    continue
                if attribs['site'] not in list(self._site2rses.keys()):
                    self._site2rses[attribs['site']] = []
                    self._site2rseids[attribs['site']] = []
                self._site2rses[attribs['site']].append(rse['rse'])
                self._site2rseids[attribs['site']].append(rse['id'])

    # Site to RSE and RSE to site conversions
    def rse2site(self, rse_name):
        """
        Translate RSE to Site name using Rucio DB  mapping.

        :param rse_name: The name of an RSE.
        :returns: the name of the site the RSE belogs to, or '' if the RSE doesn't have any site associated.
        """
        try:
            return self._rse2site[rse_name]
        except KeyError:
            return ''

    def site2rses(self, site):
        """
        Translate Site name to all the RSEs in this site.

        :param site: The name of a site
        :returns: The list of RSE names belonging to the site or [] in case the site doesn't exists or not RSE associated.
        """
        try:
            return self._site2rses[site]
        except KeyError:
            return []

    # Site to RSE and RSE to site conversions
    def rseid2site(self, rse_id):
        """
        Translate RSE to Site name using Rucio DB  mapping.

        :param rse_id: some RSE id.
        :returns: the site name the RSE with rse_id id belongs to or '' if the RSE doesn't have any site associated.
        """
        try:
            return self._rseid2site[rse_id]
        except KeyError:
            return ''

    def site2rseids(self, site):
        """
        Translate Site name to all the RSEs in this site.

        :param site: The name of a site
        :returns: The list of RSE ids belonging to the site or [] in case the site doesn't exists or not RSE associated.
        """
        try:
            return self._site2rseids[site]
        except KeyError:
            return []

    # Net time prediction
    def recover_params(self, src, dst):
        """
        Get the parameters (rate, overhead, diskrw) to calculate
        rate_pred = (size / (size / rate) + overhead) < diskrw
        used to calculate the network transfer estimation

        :param src: The source RSE name.
        :param dst: The destination RSE name.
        :returns: link, rate, overhead, diskrw
        :returns link: the true link used for parameters retrieval, could be STANDARD_LINK if the src__dst pair isn't found.
        :returns rate: the rate parameter fitter for the link.
        :returns overhead: the overhead parameter fitted for the link.
        :returns diskrw: the disk read/write limit parameter fitted for the link.
        """
        link = '__'.join([src, dst])
        try:
            values = self.model[link]
        except KeyError:
            link = 'STANDARD_LINK'
            values = self.model['STANDARD_LINK']
        return link, values['rate'], values['overhead'], values['diskrw']

    def predict_n(self, src, dst, size):
        """
        Use the parameters for the model return the network transfert estimation
        for a given link.

        :param src: The source RSE name for the transfer.
        :param dst: The destination RSE name for the transfer.
        :param size: size in bytes of the transfer.
        :returns: Number of seconds the transfer is going to take.
        """
        src = self.rse2site(src)
        dst = self.rse2site(dst)
        link = '__'.join([src, dst])
        link_true, rate, overhead, diskrw = self.recover_params(src, dst)
        if link_true == 'STANDARD_LINK':
            logging.warning('Link ' + link + ' not found, using standard parameters...')
        else:
            logging.info('I: Using ' + link + ' data from model to predict.')
        rate_pred = min((size / (size / rate) + overhead), diskrw)
        return size / rate_pred

    # Queue time prediction
    @read_session
    def get_submitted_at_rucio(self, src, dst, act, session=None):
        """
        Get the latest active transfer for the link from Rucio DB

        :param src: The source RSE name for the transfer.
        :param dst: The destination RSE name for the transfer.
        :param act: The activity of the transfer.
        :returns: a list of submittion times for all the active transfers in the src, dst, act tuple.
        """
        site_src = self.rse2site(src)
        site_dst = self.rse2site(dst)
        rses_id_src = self.site2rseids(site_src)
        rses_id_dst = self.site2rseids(site_dst)
        submitted_times = session.query(models.Request.submitted_at)\
                                 .filter(models.Request.state == models.RequestState.SUBMITTED,
                                         models.Request.source_rse_id.in_(rses_id_src),
                                         models.Request.dest_rse_id.in_(rses_id_dst),
                                         models.Request.activity == act).all()
        submitted_times = [(datetuple[0] - dt.datetime.utcfromtimestamp(0)).total_seconds() for datetuple in submitted_times]
        submitted_times.sort(reverse=True)
        return submitted_times

    def predict_q(self, src, dst, act):
        """
        Make a prediction for the queue time
        based on the TASQ (time already spend in the queue)
        of the active transfers.
        :param src: The source RSE name for the transfer.
        :param dst: The destination RSE name for the transfer.
        :param act: The activity of the transfer.
        :returns: Number of seconds the transfer is going to spend in FTS queue.
        """
        start = time.time()
        submitted = self.get_submitted_at_rucio(src, dst, act)
        if len(submitted) == 0:
            submitted = [time.time()]
        debug = True
        if debug is True:
            logging.info('Query took ' + str(time.time() - start) + ' seconds to retrieve (' + str(len(submitted)) + ') rows.')
            f = open('/tmp/forecast.log', 'a')
            f.write(src + ' --> ' + dst + ' (' + act + ') time:' + str(time.time() - start) + '\n')
            f.write(str(submitted))
            f.write('\n')
            f.close()
        submitted = np.array(submitted)
        submitted = int(time.time()) - submitted
        return ewma(submitted, span=10)[-1]

    # Overall prediction
    def predict(self, transfers):
        """
        Make a prediction for queue and network time for a collection of transfers

        :param transfers: A list of dictionaries, each of wich at least have the keys src: The name of the source RSE for the transfer. dst: The name of the destination RSE for the transfer. act: The activity of the transfer. size: The size in bytes.
        :returns: A list of the previous dictionaries extended with two new keys ntime: Number of seconds the transfer is going to spend in in the network. qtime: Number of seconds the transfer is going to spend in FTS queue.
        """
        result = []
        for transfer in transfers:
            src = transfer['src']
            dst = transfer['dst']
            act = transfer['activity']
            size = transfer['size']
            transfer['ntime'] = self.predict_n(src, dst, size)
            transfer['qtime'] = self.predict_q(src, dst, act)
            result.append(transfer)
        return result

    @read_session
    def predict_by_rule_id(self, rule_id, session=None):
        """
        Make a prediction based on the rule id.

        :param rule_id: Some rule id.
        :returns: Number of seconds the rules is going to take till is complete.
        """
        requests = session.query(models.Request).filter(models.Request.rule_id == rule_id).all()
        transfers = []
        for req in requests:
            try:
                transfers.append({'src': get_rse_name(req.source_rse_id),
                                  'dst': get_rse_name(req.dest_rse_id),
                                  'activity': req.activity,
                                  'size': req.bytes})
            except RSENotFound:
                continue
        results = self.predict(transfers)
        max_q = 0
        max_n = 0
        if len(transfers) == 0:
            logging.warning('Can\'t calculate TTC for the transfers. Probably no sources selected yet.')
            return -1, -1
        for transfer in results:
            if transfer['qtime'] > max_q:
                max_q = transfer['qtime']
            if transfer['ntime'] > max_n:
                max_n = transfer['ntime']
        return max_q, max_n
