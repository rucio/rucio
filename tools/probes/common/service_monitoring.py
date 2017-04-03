#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN) 2013
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne <ralph.vigne@cern.ch> 2015
# - Cedric Serfon, <cedric.serfon@cern.ch> 2017

import datetime
import logging
import json
import sys

import requests

from sys import stdout

logging.basicConfig(stream=stdout,
                    level=logging.ERROR,
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

LOGGER = logging.getLogger(__name__)

GRAPHITE_URL = "rucio-graphite-prod-02.cern.ch"

if len(sys.argv) != 2:
    print "Usage: service_monitoring [path to config file]"

with open(sys.argv[1]) as f:
    SERVICES = json.load(f)

for service in SERVICES:
    data = {}

    LOGGER.debug('Working on service %s' % service['id'])
    for target in service['targets']:
        # Requesting raw data
        LOGGER.debug('Requesting data for %s' % target['target'])
        url = 'http://%s/render?from=%s&until=%s&format=json&target=%s' % (GRAPHITE_URL, service['from'], service['until'], target['target'])
        r = requests.get(url)
        if r.status_code != 200:
            LOGGER.error('Failed with status code %s when requesting data from %s' % (r.status_code, url))
            continue

        # Create list of numericValue for XML report
        for metric in r.json():
            valueID = target['name'].replace('{target}', metric['target'])
            data[valueID] = {'value': metric['datapoints'][-1][0], 'desc': target['desc'] if 'desc' in target else "None given"}
            LOGGER.debug('Setting %s to %s' % (valueID, data[valueID]['value']))

    # Derive availability
    LOGGER.debug('Derive availability based on %s' % service['availability']['metric'])
    if service['availability']['metric'] != '':
        url = 'http://%s/render?from=%s&until=%s&format=json&target=alias(%s, "availability")' % (GRAPHITE_URL, service['from'], service['until'], service['availability']['metric'])
        LOGGER.debug(url)
        r = requests.get(url)
        if r.status_code != 200:
            LOGGER.error('Failed with status code %s when requesting data from %s' % (r.status_code, url))
            continue
        LOGGER.debug(r.json())
        value = r.json()[0]['datapoints'][-1][0]
        if value is None or (value == 0 and len(r.json()[0]['datapoints']) > 1):  # Happens occasionally
            try:
                value = r.json()[0]['datapoints'][-2][0]
            except:
                pass
        if 'mapping' in service['availability'] and service['availability']['mapping'] != '':
            mapping = service['availability']['mapping'].replace('{value}', str(value))
            LOGGER.debug('Availability mapping function: %s' % (mapping))
            try:
                availability = eval(mapping)
            except:
                LOGGER.error('Failed to derive availability.\nURL: %s\nMapping: %s\nDatapoints: %s' % (url, mapping, r.json()))
                LOGGER.error(sys.exc_info()[0])
        else:
            availability = value
        LOGGER.debug('Availability of %s: %s' % (service['id'], availability))

        if availability != 100:    # For a week or so, we print if not 100 and set report 100 to SLS
            print 'Availability of %s: %s (value: %s)' % (service['id'], availability, value)
        if availability > 10:
            status = 'available'
        elif availability <= 10:
            status = 'degraded'
        else:
            status = 'unavailable'

    # Creating XML report
    xml_str = '<serviceupdate xmlns="http://sls.cern.ch/SLS/XML/update">'
    xml_str += '<id>%s</id>' % service['id']
    xml_str += '<status>%s</status>' % status
    xml_str += '<availabilitydesc>%s</availabilitydesc>' % service['availability']['info']
    xml_str += '<webpage>' + service['webpage'] + '</webpage>'
    xml_str += '<contact>rucio-admin@cern.ch</contact>'
    xml_str += '<timestamp>%s</timestamp>' % (datetime.datetime.now().isoformat().split('.')[0])
    xml_str += '<data><numericvalue name="xsls_availability">%s</numericvalue>' % availability
    for metric in data:
        xml_str += '<numericvalue name="%s" desc="%s">%s</numericvalue>' % (metric, data[metric]['desc'], data[metric]['value'])
    xml_str += '</data>'
    xml_str += '</serviceupdate>'
    LOGGER.debug(xml_str)
    r = requests.post("http://xsls.cern.ch", files={'file': xml_str})
