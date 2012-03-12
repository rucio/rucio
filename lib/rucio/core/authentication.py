# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012

import datetime
import uuid

from sqlalchemy import create_engine
from sqlalchemy import and_, update, text
from sqlalchemy.orm import sessionmaker, scoped_session

from rucio.common.config import config_get
import rucio.db.models1 as m

engine = create_engine(config_get('database', 'default'))
m.register_models(engine)  # this only creates the necessary tables, should be done once somewhere else and then never again
s = scoped_session(sessionmaker(bind=engine))


def get_auth_token_user_pass(account, username, password):
    """Authenticate a Rucio account temporarily via username and password."""

    if account == 'ddmlab' and username == 'mlassnig' and password == 'secret':

        # create new token
        token = str(uuid.uuid4()).replace('-', '')

        s.add(m.Authentication(account=account, token=token))
        s.commit()

        return token

    return None


def validate_auth_token(account, token):
    """Validate an authentication token."""

    q = s.query(m.Authentication.lifetime).filter(and_(m.Authentication.account == account, m.Authentication.token == token, m.Authentication.lifetime > datetime.datetime.utcnow()))

    r = q.all()

    if r is not None and r != []:
        q.update({'lifetime': datetime.datetime.utcnow() + datetime.timedelta(seconds=3600)})
        s.commit()
        return r[0][0]

    return None
