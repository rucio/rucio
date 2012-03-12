# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012

import datetime
import uuid

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import rucio.db.models1 as models

engine = create_engine('sqlite:////tmp/rucio.db', echo=True)
Session = sessionmaker(bind=engine)
s = Session()
models.register_models(engine)  # this only creates the necessary tables, should be done once somewhere else and then never again


def get_auth_token_user_pass(account, username, password):
    """Authenticate a Rucio account temporarily via username and password."""

    if account == 'ddmlab' and username == 'mlassnig' and password == 'secret':

        # create new token
        token = str(uuid.uuid4()).replace('-', '')

        # insert token in database
        new_auth = models.Authentication()
        new_auth.token = token
        new_auth.account = account
        s.add(new_auth)
        s.commit()

        return token

    return None
