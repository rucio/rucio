# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013

"""
SQLAlchemy models for Rucio tests
"""

from datetime import datetime

from sqlalchemy import Column, DateTime, PrimaryKeyConstraint

from rucio.common.utils import generate_uuid
from rucio.db.constants import FTSState
from rucio.db.models import ModelBase, String
from rucio.db.session import BASE
from rucio.db.types import GUID


class MockFTSTransfer(BASE, ModelBase):
    __tablename__ = 'mock_fts_transfers'
    transfer_id = Column(GUID(), default=generate_uuid)
    start_time = Column(DateTime, default=datetime.utcnow)
    last_modified = Column(DateTime, default=datetime.utcnow)
    state = Column(FTSState.db_type(name='MOCK_FTS_TRANSFERS_STATE_CHK'), default=FTSState.SUBMITTED)
    transfer_metadata = Column(String(4000))
    _table_args = (PrimaryKeyConstraint('transfer_id', name='MOCK_FTS_TRANSFERS_PK'), )


def register_models(engine):
    """
    Creates database tables for all models with the given engine
    """
    models = (MockFTSTransfer, )

    for model in models:
        model.metadata.create_all(engine)


def unregister_models(engine):
    """
    Drops database tables for all models with the given engine
    """
    models = (MockFTSTransfer, )

    for model in models:
        model.metadata.drop_all(engine)
