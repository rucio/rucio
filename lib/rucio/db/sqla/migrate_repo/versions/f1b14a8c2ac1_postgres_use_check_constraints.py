# -*- coding: utf-8 -*-
# Copyright 2019-2020 CERN
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
# - Robert Illingworth <illingwo@fnal.gov>, 2019
# - Mario Lassnig <mario.lassnig@cern.ch>, 2020

''' postgres_use_check_constraints '''

# Alembic revision identifiers
revision = 'f1b14a8c2ac1'
down_revision = 'b8caac94d7f0'


def upgrade():
    # not needed anymore after SQLAlchemy 1.3.8
    pass


def downgrade():
    # not needed anymore after SQLAlchemy 1.3.8
    pass
