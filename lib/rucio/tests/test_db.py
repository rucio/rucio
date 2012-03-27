# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne,  <vincent.garonne@cern.ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012

import datetime
import random

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import rucio.db.models1 as models

engine = create_engine('sqlite:///:memory:', echo=True)
session = sessionmaker(bind=engine)()
models.unregister_models(engine)
models.register_models(engine)
