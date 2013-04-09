#!/usr/bin/env python

import json

from rucio.common.utils import execute

if __name__ == '__main__':

    fname = 'fts_job.json'
    with open(fname) as f:
        parameters = json.loads(f.read())
        parameters = json.dumps(parameters)
    cmd = "curl --insecure  --cert ./x509up --key ./x509up --header \"Content-type: application/json\" --data '%(parameters)s' --request POST https://fts3-pilot.cern.ch:8446/jobs" % locals()
    print cmd
    exitcode, out, err = execute(cmd)
    print out
    print err
