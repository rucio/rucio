# Copyright 2012-2019 CERN for the benefit of the ATLAS collaboration.
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
# - Vincent Garonne, <vgaronne@gmail.com>, 2012-2019
# - Wen Guan, <wguan.icedew@gmail.com>, 2014
# - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2018

"""
Reaper is a daemon to manage file deletion
"""

import argparse
import signal
import sys

from rucio.daemons.reaper.reaper import run, stop


def get_parser():
    """
    Returns the argparse parser.
    """
    parser = argparse.ArgumentParser(description="The Reaper daemon is responsible for replica deletion. It deletes them by checking if there are replicas that are not locked and have a tombstone to indicate that they can be deleted.", epilog='''
Upload a file and prepare the rules and replicas for deletion by using the judge-cleaner daemon::

  $ rucio upload --rse MOCK --scope mock --name file filename.txt
  $ rucio add-rule mock:file 1 MOCK2 --lifetime 1
  $ rucio-judge-cleaner --run-once

Check if the replica was created::

  $ rucio list-file-replica mock:file
  +---------+--------+------------+-----------+---------------------------------------------------------+
  | SCOPE   | NAME   | FILESIZE   | ADLER32   | RSE: REPLICA                                            |
  |---------+--------+------------+-----------+---------------------------------------------------------|
  | mock    | file   | 1.542 kB   | 1268ee71  | MOCK: file://localhost:0/tmp/rucio_rse/mock/15/58/file  |
  +---------+--------+------------+-----------+---------------------------------------------------------+

Run the daemon::

  $ rucio-reaper --run-once

Check if the replica exists::

  $ rucio list-file-replica mock:file
  +---------+--------+------------+-----------+---------------------------------------------------------+
  | SCOPE   | NAME   | FILESIZE   | ADLER32   | RSE: REPLICA                                            |
  |---------+--------+------------+-----------+---------------------------------------------------------|
  +---------+--------+------------+-----------+---------------------------------------------------------+
 ''')
    parser.add_argument("--run-once", action="store_true", default=False, help='One iteration only')
    parser.add_argument("--total-workers", action="store", default=1, type=int, help='Total number of workers per process')
    parser.add_argument("--threads-per-worker", action="store", default=None, type=int, help='Total number of threads created by each worker')
    parser.add_argument("--chunk-size", action="store", default=10, type=int, help='Chunk size')
    parser.add_argument("--scheme", action="store", default=None, type=str, help='Force the reaper to use a particular protocol, e.g., mock.')
    parser.add_argument('--greedy', action='store_true', default=False, help='Greedy mode')
    parser.add_argument('--exclude-rses', action="store", default=None, type=str, help='RSEs expression to exclude RSEs')
    parser.add_argument('--include-rses', action="store", default=None, type=str, help='RSEs expression to include RSEs')
    parser.add_argument('--rses', nargs='+', type=str, help='List of RSEs')
    parser.add_argument('--delay-seconds', action="store", default=3600, type=int, help='Delay to retry failed deletion')
    return parser


def main(argv=None):
    """
    The main reaper method called by the command.

    :param argv: Command-line arguments. Default to  sys.argv if not set.
    """
    signal.signal(signal.SIGTERM, stop)

    if argv is None:
        argv = sys.argv[1:]

    parser = get_parser()
    args = parser.parse_args(argv)
    try:
        run(total_workers=args.total_workers, chunk_size=args.chunk_size, greedy=args.greedy,
            once=args.run_once, scheme=args.scheme, rses=args.rses, threads_per_worker=args.threads_per_worker,
            exclude_rses=args.exclude_rses, include_rses=args.include_rses, delay_seconds=args.delay_seconds)
    except KeyboardInterrupt:
        stop()
