'''
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Vincent Garonne, <vincent.garonne@cern.ch>, 2013-2017
'''
from rucio.db.sqla.session import get_session


def test_db_connection():
    """ DB (CORE): Test db connection """
    session = get_session()
    if session.bind.dialect.name == 'oracle':
        session.execute('select 1 from dual')
    else:
        session.execute('select 1')
    session.close()
