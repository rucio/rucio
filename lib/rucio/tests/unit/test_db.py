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

#ALTER TABLE dataset_properties drop CONSTRAINT fk_dataset_properties;
#ALTER TABLE file_properties drop CONSTRAINT fk_file_properties;
#ALTER TABLE replication_rules drop CONSTRAINT fk_replication_rules;
#ALTER TABLE file_replicas drop CONSTRAINT fk_file_replicas;
#ALTER TABLE dataset_file_association drop CONSTRAINT fk_dataset_file_association;
#ALTER TABLE dataset_file_association drop CONSTRAINT fk2_dataset_file_association;

#ALTER TABLE dataset_properties add CONSTRAINT fk_dataset_properties
#FOREIGN KEY (scope, dsn) REFERENCES datasets (scope, dsn);
#ALTER TABLE file_properties add CONSTRAINT fk_file_properties
#FOREIGN KEY (scope, lfn) REFERENCES files (scope, lfn);
#ALTER TABLE replication_rules add CONSTRAINT fk_replication_rules
#FOREIGN KEY (scope, lfn) REFERENCES files (scope, lfn);
#ALTER TABLE file_replicas add CONSTRAINT fk_file_replicas
#FOREIGN KEY (scope, lfn) REFERENCES files (scope, lfn);
#ALTER TABLE dataset_contents add CONSTRAINT fk_dataset_file_association
#FOREIGN KEY (scope_lfn, lfn) REFERENCES files (scope, lfn);
#ALTER TABLE dataset_contents add CONSTRAINT fk2_dataset_file_association
#FOREIGN KEY (scope_dsn, dsn) REFERENCES datasets (scope, dsn);
