import json
import mmh3
import math
from dataclasses import dataclass


def hash_to_unit_interval(s: str) -> float:
    """Hashes a string onto the unit interval (0, 1]"""
    return (mmh3.hash128(s) + 1) / 2**128


class XCaches:
    def __init__(self, heartbeats=None):
        """ creates map of XCaches based on their heartbeats """
        self.sites = {}

        if not heartbeats:
            return
        for hb in heartbeats:
            instance = json.loads(hb['payload'])
            site = instance['site']
            if site not in self.sites:
                self.sites[site] = []
            self.sites[site].append(Node(instance['address'], float(instance['size'])))
        print(self.sites)

    def determine_responsible_node(self, site: str, key: str):
        """Determines which node of a site is responsible for the provided key."""
        if site not in self.sites:
            return ''
        rn = max(
            self.sites[site], key=lambda node: node.compute_weighted_score(key), default=None)
        return rn.name


@dataclass
class Node:
    """Class representing a node that is assigned keys as part of a weighted rendezvous hash."""
    name: str
    weight: float

    def compute_weighted_score(self, key: str):
        score = hash_to_unit_interval(f"{self.name}: {key}")
        log_score = 1.0 / -math.log(score)
        return self.weight * log_score


# # ------------ Test --------------
# import string
# import random
# heartbeats = [
#     {'readable': 'xcache', 'hostname': 'slate01', 'pid': 0, 'thread_name': 'thread', 'updated_at': 'Fri, 14 Jul 2023 19:05:04 UTC',
#         'created_at': 'Fri, 14 Jul 2023 00:58:01 UTC', 'payload': '{"site": "UC-AF", "instance": "slate01", "address": "192.170.240.18:1094", "size": "35927165916"}'},
#     {'readable': 'xcache', 'hostname': 'slate02', 'pid': 0, 'thread_name': 'thread', 'updated_at': 'Fri, 14 Jul 2023 19:05:04 UTC',
#      'created_at': 'Fri, 14 Jul 2023 00:58:01 UTC', 'payload': '{"site": "UC-AF", "instance": "slate02", "address": "192.170.240.19:1094", "size": "25927165916"}'},
#     {'readable': 'xcache', 'hostname': 'slate01', 'pid': 0, 'thread_name': 'thread', 'updated_at': 'Fri, 14 Jul 2023 19:05:04 UTC',
#      'created_at': 'Fri, 14 Jul 2023 00:58:01 UTC', 'payload': '{"site": "MWT2", "instance": "slate01", "address": "192.170.240.20:1094", "size": "127165916"}'}
# ]
# xcaches = XCaches(heartbeats=heartbeats)
# print('BNL:', xcaches.determine_responsible_node('BNL', 'root://sdf.adf./adfasdf'))
# print('MWT2:', xcaches.determine_responsible_node('MWT2', 'root://sdf.adf./adfasdf'))
# counts = {}
# for t in range(10000):
#     s = string.ascii_lowercase + string.digits
#     ip = xcaches.determine_responsible_node('UC-AF', ''.join(random.sample(s, 10)))
#     if ip not in counts:
#         counts[ip] = 1
#     counts[ip] += 1
# print('UC-AF', counts)
