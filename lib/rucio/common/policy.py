# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2016-2017
# - Martin Barisits, <martin.barisits@cern.ch>, 2017

import json
import os
import re
import logging
import sys

from ConfigParser import NoOptionError, NoSectionError
from datetime import datetime, timedelta
from dogpile.cache import make_region
from dogpile.cache.api import NoValue
from sqlalchemy.orm.exc import NoResultFound

import rucio.core.did
import rucio.core.lock
import rucio.core.rule

from rucio.db.sqla import models
from rucio.db.sqla.constants import DIDType
from rucio.db.sqla.session import read_session, transactional_session
from rucio.common.config import config_get
from rucio.common.exception import ScratchDiskLifetimeConflict, DataIdentifierNotFound
from rucio.core.account import has_account_attribute
from rucio.core.rse import list_rse_attributes

REGION = make_region().configure('dogpile.cache.memory',
                                 expiration_time=1800)

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')


def get_vo():
    vo_name = REGION.get('VO')
    if isinstance(vo_name, NoValue):
        try:
            vo_name = config_get('common', 'vo')
        except NoOptionError:
            vo_name = 'atlas'
        REGION.set('VO', vo_name)
    return vo_name


def get_scratchdisk_lifetime():
    scratchdisk_lifetime = REGION.get('scratchdisk_lifetime')
    if isinstance(scratchdisk_lifetime, NoValue):
        try:
            scratchdisk_lifetime = config_get('policy', 'scratchdisk_lifetime')
            scratchdisk_lifetime = int(scratchdisk_lifetime)
        except (NoOptionError, NoSectionError, ValueError):
            scratchdisk_lifetime = 14
        REGION.set('scratchdisk_lifetime', scratchdisk_lifetime)
    return scratchdisk_lifetime


def get_lifetime_policy():
    lifetime_dict = REGION.get('lifetime_dict')
    if isinstance(lifetime_dict, NoValue):
        lifetime_dict = {'data': [], 'mc': [], 'valid': [], 'other': []}
        try:
            lifetime_dir = config_get('lifetime', 'directory')
        except (NoSectionError, NoOptionError):
            lifetime_dir = '/opt/rucio/etc/policies'
        for dtype in ['data', 'mc', 'valid', 'other']:
            input_file_name = '%s/config_%s.json' % (lifetime_dir, dtype)
            if os.path.isfile(input_file_name):
                with open(input_file_name, 'r') as input_file:
                    lifetime_dict[dtype] = json.load(input_file)
        REGION.set('lifetime_dict', lifetime_dict)
    return lifetime_dict


@read_session
def define_eol(scope, name, rses, session=None):
    """
    ATLAS policy for rules on SCRATCHDISK

    :param scope:    Scope of the DID.
    :param name:     Name of the DID.
    :param rses:     List of RSEs.
    :param session:  The database session in use.
    """
    vo_name = get_vo()
    if vo_name != 'atlas':
        return None

    # Check if on ATLAS managed space
    if [rse for rse in rses if list_rse_attributes(rse=None, rse_id=rse['id'], session=session).get('type') in ['LOCALGROUPDISK', 'LOCALGROUPTAPE', 'GROUPDISK', 'GROUPTAPE']]:
        return None
    # Now check the lifetime policy
    try:
        did = session.query(models.DataIdentifier).filter(models.DataIdentifier.scope == scope,
                                                          models.DataIdentifier.name == name).one()
    except NoResultFound:
        return None
    policy_dict = get_lifetime_policy()
    did_type = 'other'
    if scope.startswith('mc'):
        did_type = 'mc'
    elif scope.startswith('data'):
        did_type = 'data'
    elif scope.startswith('valid'):
        did_type = 'valid'
    else:
        did_type = 'other'
    for policy in policy_dict[did_type]:
        if 'exclude' in policy:
            to_exclude = False
            for key in policy['exclude']:
                meta_key = None
                if key not in ['datatype', 'project', ]:
                    if key == 'stream':
                        meta_key = 'stream_name'
                    elif key == 'tags':
                        meta_key = 'version'
                else:
                    meta_key = key
                values = policy['exclude'][key]
                for value in values:
                    value = value.replace('%', '.*')
                    if meta_key and did[meta_key] and value and re.match(value, did[meta_key]):
                        to_exclude = True
                        break
                if to_exclude:
                    break
            if to_exclude:
                continue
        if 'include' in policy:
            match_policy = True
            for key in policy['include']:
                meta_key = None
                if key not in ['datatype', 'project', ]:
                    if key == 'stream':
                        meta_key = 'stream_name'
                    elif key == 'tags':
                        meta_key = 'version'
                    else:
                        continue
                else:
                    meta_key = key
                values = policy['include'][key]
                to_keep = False
                for value in values:
                    value = value.replace('%', '.*')
                    if meta_key and did[meta_key] and value and re.match(value, did[meta_key]):
                        to_keep = True
                        break
                match_policy = match_policy and to_keep
                if not to_keep:
                    match_policy = False
                    break
            if match_policy:
                if int(policy['age']) >= 12:
                    years = int(int(policy['age']) / 12)
                    months = int(policy['age']) - years * 12
                    lifetime_value = 365 * years + 30 * months
                else:
                    lifetime_value = int(policy['age']) * 30
                if int(policy['extension']) >= 12:
                    years = int(int(policy['extension']) / 12)
                    months = int(policy['extension']) - years * 12
                    extension = 365 * years + 30 * months
                else:
                    extension = int(policy['extension']) * 30

                default_eol_at = did.created_at + timedelta(days=lifetime_value)
                if default_eol_at > datetime.utcnow():
                    eol_at = default_eol_at
                elif did.accessed_at:
                    eol_at = did.accessed_at + timedelta(days=extension)
                    if eol_at < default_eol_at:
                        eol_at = default_eol_at
                else:
                    eol_at = default_eol_at

                return eol_at
    return None


def get_lifetime_exceptions():
    lifetime_exceptions = REGION.get('lifetime_exceptions')
    if isinstance(lifetime_exceptions, NoValue):
        exceptions = {}
        try:
            lifetime_dir = config_get('lifetime', 'directory')
        except (NoSectionError, NoOptionError):
            lifetime_dir = '/opt/rucio/etc/policies'
        for dtype in ['data', 'mc', 'valid', 'other']:
            input_file_name = '%s/exceptions_%s.json' % (lifetime_dir, dtype)
            if os.path.isfile(input_file_name):
                with open(input_file_name, 'r') as input_file:
                    for exception in json.load(input_file):
                        date, extension_date = exception['date'], exception.get('expiration_date')
                        date = datetime.strptime(date, '%Y-%m-%d')
                        if not extension_date:
                            extension_date = date + timedelta(days=90)
                        else:
                            extension_date = datetime.strptime(extension_date, '%Y-%m-%d')
                        for dsn in exception['datasets']:
                            if dsn in exceptions:
                                if exceptions[dsn] < extension_date:
                                    # print 'Lifetime for %s will be extended from %s to %s' % (dsn, exceptions[dsn], extension_date)
                                    exceptions[dsn] = extension_date
                            else:
                                exceptions[dsn] = extension_date

        REGION.set('lifetime_exceptions', exceptions)
    return exceptions


@read_session
def get_scratch_policy(account, rses, lifetime, session=None):
    """
    ATLAS policy for rules on SCRATCHDISK

    :param account:  Account of the rule.
    :param rses:     List of RSEs.
    :param lifetime: Lifetime.
    :param session:  The database session in use.
    """

    vo_name = get_vo()
    scratchdisk_lifetime = get_scratchdisk_lifetime()
    if vo_name == 'atlas':
        # Check SCRATCHDISK Policy
        if not has_account_attribute(account=account, key='admin', session=session) and (lifetime is None or lifetime > 60 * 60 * 24 * scratchdisk_lifetime):
            # Check if one of the rses is a SCRATCHDISK:
            if [rse for rse in rses if list_rse_attributes(rse=None, rse_id=rse['id'], session=session).get('type') == 'SCRATCHDISK']:
                if len(rses) == 1:
                    lifetime = 60 * 60 * 24 * scratchdisk_lifetime - 1
                else:
                    raise ScratchDiskLifetimeConflict()
        return lifetime
    return None


@transactional_session
def archive_localgroupdisk_datasets(scope, name, session=None):
    """
    ATLAS policy to archive a dataset which has a replica on LOCALGROUPDISK

    :param scope:    Scope of the dataset.
    :param name:     Name of the dataset.
    :param session:  The database session in use.
    """

    vo_name = get_vo()
    if vo_name != 'atlas':
        return

    rses_to_rebalance = []

    # Check if the archival dataset already exists
    try:
        rucio.core.did.get_did(scope='archive', name=name, session=session)
        return
    except DataIdentifierNotFound:
        pass

    # Check if the dataset has a rule on a LOCALGROUPDISK
    for lock in rucio.core.lock.get_dataset_locks(scope=scope, name=name, session=session):
        if 'LOCALGROUPDISK' in lock['rse']:
            rses_to_rebalance.append({'rse': lock['rse'], 'account': lock['account']})

    # There is at least one rule on LOCALGROUPDISK
    if rses_to_rebalance:
        content = [x for x in rucio.core.did.list_content(scope=scope, name=name, session=session)]
        if len(content) > 0:
            # Create the archival dataset
            did = rucio.core.did.get_did(scope=scope, name=name, session=session)
            meta = rucio.core.did.get_metadata(scope=scope, name=name, session=session)
            new_meta = {k: v for k, v in meta.items() if k in ['project', 'datatype', 'run_number', 'stream_name', 'prod_step', 'version', 'campaign', 'task_id', 'panda_id'] and v is not None}
            rucio.core.did.add_did(scope='archive',
                                   name=name,
                                   type=DIDType.DATASET,
                                   account=did['account'],
                                   statuses={},
                                   meta=new_meta,
                                   rules=[],
                                   lifetime=None,
                                   dids=[],
                                   rse=None,
                                   session=session)
            rucio.core.did.attach_dids(scope='archive', name=name, dids=content, account=did['account'], session=session)
            if not did['open']:
                rucio.core.did.set_status(scope='archive', name=name, open=False, session=session)

            for rse in rses_to_rebalance:
                rucio.core.rule.add_rule(dids=[{'scope': 'archive', 'name': name}],
                                         account=rse['account'],
                                         copies=1,
                                         rse_expression=rse['rse'],
                                         grouping='DATASET',
                                         weight=None,
                                         lifetime=None,
                                         locked=False,
                                         subscription_id=None,
                                         ignore_account_limit=True,
                                         ignore_availability=True,
                                         session=session)
            logging.debug('Re-Scoped %s:%s' % (scope, name))
