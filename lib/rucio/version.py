"""
@copyright: European Organization for Nuclear Research (CERN)
@contact: U{ph-adp-ddm-lab@cern.ch<mailto:ph-adp-ddm-lab@cern.ch>}
@license: Licensed under the Apache License, Version 2.0 (the "License");
You may not use this file except in compliance with the License.
You may obtain a copy of the License at U{http://www.apache.org/licenses/LICENSE-2.0}
@author:
- Vincent Garonne, <vincent.garonne@cern.ch>, 2011

"""

try:
    from rucio.vcsversion import version_info
except ImportError:
    version_info = {'branch_nick': u'LOCALBRANCH',
                    'revision_id': 'LOCALREVISION',
                    'revno': 0}

RUCIO_VERSION = ['2012', '1', None]
YEAR, COUNT, REVSISION = RUCIO_VERSION
FINAL = False   # This becomes true at Release Candidate time


def canonical_version_string():
    return '.'.join(filter(None, RUCIO_VERSION))


def version_string():
    if FINAL:
        return canonical_version_string()
    else:
        return '%s-dev' % (canonical_version_string(),)


def vcs_version_string():
    return "%s:%s" % (version_info['branch_nick'], version_info['revision_id'])


def version_string_with_vcs():
    return "%s-%s" % (canonical_version_string(), vcs_version_string())
