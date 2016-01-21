# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2016

import logging

from rucio.db.sqla.session import read_session


class JediDIDCollector():
    def __init__(self, queue):
        self.queue = queue
        self.max_tid = 0

    @read_session
    def get_dids(self, session=None):
        query = """select t.jeditaskid, t.username, t.status, d.datasetname from ATLAS_PANDA.JEDI_TASKS t
        inner join ATLAS_PANDA.JEDI_DATASETS d
        on t.jeditaskid = d.jeditaskid
        where t.creationdate > SYS_EXTRACT_UTC(systimestamp) - 5/(24*60) and t.tasktype = 'anal' and t.prodsourcelabel = 'user'
        and d.type = 'input'
        order by d.jeditaskid asc"""

        tasks = session.execute(query)

        for t in tasks.fetchall():
            status = t[2]
            if status == 'running':
                continue
            tid = t[0]
            if tid < self.max_tid:
                continue

            logging.debug("Received task: " + str(t))
            did = t[3].split(':')
            self.queue.put((did[0], did[1]))
            self.max_tid = tid
