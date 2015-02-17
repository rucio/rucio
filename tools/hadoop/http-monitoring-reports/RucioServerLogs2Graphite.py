#!/bin/python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2015

import re
import socket
import time
import sys

from collections import defaultdict
from collections import OrderedDict

mapper = OrderedDict({'time': 1,  # (01) Date/Time [YYYY-MM-DD HH:MM:SS] => [%{%Y-%m-%d %H:%M:%S}t]
                      #  'seconds': 2,  # (01) Date/Time [YYYY-MM-DD HH:MM:SS] => [%{%Y-%m-%d %H:%M:%S}t]
                      'fqdn': 3,   # (02) Backen (canonical server) name e.g. rucio-server-prod-11 => %v
                      'host': 4,   # (02) Backen (canonical server) name e.g. rucio-server-prod-11 => %v
                      #  'loadbalancer': 4,  # (03) Load balancer IP => %h
                      #  'client_ip': 5,  # (04) Client IP => %{X-Forwarded-For}i
                      #  'request_id': 6,  # (05) Rucio Request ID => %{X-Rucio-RequestId}i
                      #  'status': 7,  # (06) Status => %>s
                      'request_size': 9,  # (07) Request size in bytes => %I
                      'response_size': 10,  # (08) Response size in bytes => %B
                      'response_time_in_micros': 11,  # (09) Response time in microseconds => %D
                      #  'request':  11,  # (10) First line of request => \"%r\"
                      'http_verb': 13,  # (10) First line of request => \"%r\"
                      #  'resource':  13,  # (10) First line of request => \"%r\"
                      #  'protocol_version':  14,  # (10) First line of request => \"%r\"
                      'account': 17,  # (11) "Rucio Account" => \"%{X-Rucio-Auth-Token}i\"
                      #  'certificate':  16,  # (11) "Rucio Account" => \"%{X-Rucio-Auth-Token}i\"
                      #  'useragent':  17   # (12) User Agent, including also the script name (as derived from __main__) e.g. "my-script rucio-clients/0.2.13" => \"%{User-Agent}i\"
                      })


key_mapper = [mapper[key] for key in mapper][::-1]
keys = [key for key in mapper][::-1]

GRAPHITE_HOST = 'rucio-graphite-int.cern.ch'
GRAPHITE_PORT = 2003
GRAPHITE_SCOPE = 'rucio.http-monitoring'

pattern = re.compile("^\\[(.*):(.*?)\\]\t((.*?)\\..*?)\t(\\S+)\t(\\S+)\t(\\S+)\t(\\S+)\t(\\S+)\t(\\S+)\t(\\S+)\t\"((\\S+)\\s+(\\S+)\\s+(\\S+))\"\t\"((.*?)-.*?)\"\t\"(.*?)\"$")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
timestamp = 0
events = []

for line in sys.stdin:
    try:
        attr = pattern.match(line).group(*key_mapper)
        if not re.match('[0-9]{,4}-[0-9]{,2}-[0-9]{,2} [0-9]{,2}:[0-9]{,2}', attr[keys.index('time')]):
            continue
        if attr[keys.index('host')].startswith('rucio-server-prod-05') or attr[keys.index('host')].startswith('rucio-server-prod-06'):
            continue
        new_minute = (timestamp < int(time.mktime(time.strptime(attr[keys.index('time')], '%Y-%m-%d %H:%M'))))
    except Exception:
        continue
    if new_minute:  # New lower started
        # Report stats to Graphite
        message = "%s.%s.%s.%s" % (GRAPHITE_SCOPE,
                                   attr[keys.index('host')],
                                   attr[keys.index('account')] if attr[keys.index('account')] != '' else 'unknown',
                                   attr[keys.index('http_verb')])
        for metric in events:
            for value in events[metric].keys():
                sock.sendto("%s.%s %s %s\n" % (message, value, events[metric][value], timestamp), (GRAPHITE_HOST, GRAPHITE_PORT))
        # Reset stats
        del(events)
        events = defaultdict(lambda: {'count': 0,
                                      'request_size.lower': None,
                                      'request_size.upper': None,
                                      'request_size.sum': 0,
                                      'response_size.lower': None,
                                      'response_size.upper': None,
                                      'response_size.sum': 0,
                                      'response_time_in_micros.lower': None,
                                      'response_time_in_micros.upper': None,
                                      'response_time_in_micros.sum': 0})
        timestamp = int(time.mktime(time.strptime(attr[keys.index('time')], '%Y-%m-%d %H:%M')))
    # Update stats entry
    e = events[(attr[keys.index('host')], attr[keys.index('account')], attr[keys.index('http_verb')])]
    for metric in ['request_size', 'response_size', 'response_time_in_micros']:
        e['count'] += 1
        e[metric + '.sum'] += int(attr[keys.index(metric)])
        e[metric + '.lower'] = int(attr[keys.index(metric)]) if (e[metric + '.lower'] > attr[keys.index(metric)]) or (e[metric + '.lower'] is None) else e[metric + '.lower']
        e[metric + '.upper'] = int(attr[keys.index(metric)]) if (e[metric + '.upper'] < attr[keys.index(metric)]) else e[metric + '.upper']  # In case of None, True. Thus no None check
