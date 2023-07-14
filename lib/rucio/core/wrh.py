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
            self.sites[site].append(Node(instance['address'], instance['size']))
        print(self.sites)

    def determine_responsible_node(self, site: str, key: str):
        """Determines which node of a site is responsible for the provided key."""
        if site not in self.sites:
            return ''
        return max(
            self.sites[site], key=lambda node: node.compute_weighted_score(key), default=None)


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
# import random
# import string
# heartbeats = {
#     "LRZ-LMU": {
#         "servers": [["129.187.139.130", "100"], ["129.187.139.131", "200"]],
#         "ranges": [[1, 0.5], [0, 1]]
#     },
#     "Birmingham": {"servers": [["193.62.56.109", ""]], "ranges": [[0, 1]]},
#     "BNL": {"servers": [["10.42.38.81", "2337187217408"]], "ranges": [[0, 1]]}
# }
# xcaches = XCaches(heartbeats=heartbeats)
# print(xcaches.determine_responsible_node('BNL', 'root://sdf.adf./adfasdf'))
# print(xcaches.determine_responsible_node('Birmingham', 'root://sdf.adf./adfasdf'))
# counts = {}
# for t in range(10000):
#     s = string.ascii_lowercase + string.digits
#     ip = xcaches.determine_responsible_node('LRZ-LMU', ''.join(random.sample(s, 10))).name
#     if ip not in counts:
#         counts[ip] = 1
#     counts[ip] += 1
# print(counts)
