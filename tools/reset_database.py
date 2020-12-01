#!/usr/bin/env python3
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012, 2014
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2015
# - Gabriele Gaetano Fronze' <gabriele.fronze@to.infn.it>, 2020

import sys
import os.path
base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_path)
os.chdir(base_path)

from argparse import ArgumentParser  # noqa: E402

from rucio.db.sqla.util import build_database, destroy_database, drop_everything, create_root_account, create_base_vo  # noqa: E402

if __name__ == '__main__':

    parser = ArgumentParser()
    parser.add_argument('-d', '--drop-everything', action="store_true", default=False, help='Drop all tables and constraints')
    args = parser.parse_args()

    if args.drop_everything:
        drop_everything()
    else:
        destroy_database()

    build_database()
    create_base_vo()
    create_root_account()
