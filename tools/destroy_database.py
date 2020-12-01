#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Gabriele Gaetano Fronze' <gabriele.fronze@to.infn.it>, 2020

import sys
import os.path
base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_path)
os.chdir(base_path)

import argparse  # noqa: E402

from rucio.db.sqla.util import destroy_database, drop_everything  # noqa: E402

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("--drop-everything", action="store_true", default=False, help='Drop all tables+constraints')
    args = parser.parse_args()
    if args.drop_everything:
        drop_everything()
    else:
        destroy_database()
