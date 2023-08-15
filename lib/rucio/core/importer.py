# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

from typing import TYPE_CHECKING

from rucio.common.config import config_get
from rucio.common.exception import RSEOperationNotSupported
from rucio.common.types import InternalAccount
from rucio.core import rse as rse_module, distance as distance_module, account as account_module, identity as identity_module
from rucio.db.sqla import models
from rucio.db.sqla.constants import RSEType, AccountType, IdentityType
from rucio.db.sqla.session import transactional_session

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


@transactional_session
def import_rses(rses, rse_sync_method='edit', attr_sync_method='edit', protocol_sync_method='edit', vo='def', *, session: "Session"):
    new_rses = []
    for rse_name in rses:
        rse = rses[rse_name]
        if isinstance(rse.get('rse_type'), str):
            rse['rse_type'] = RSEType(rse['rse_type'])

        if rse_module.rse_exists(rse_name, vo=vo, include_deleted=False, session=session):
            # RSE exists and is active
            rse_id = rse_module.get_rse_id(rse=rse_name, vo=vo, session=session)
            selected_rse_properties = {key: rse[key] for key in rse if key in rse_module.MUTABLE_RSE_PROPERTIES}
            rse_module.update_rse(rse_id=rse_id, parameters=selected_rse_properties, session=session)
        elif rse_module.rse_exists(rse_name, vo=vo, include_deleted=True, session=session):
            # RSE exists but in deleted state
            # Should only modify the RSE if importer is configured for edit or hard sync
            if rse_sync_method in ['edit', 'hard']:
                rse_id = rse_module.get_rse_id(rse=rse_name, vo=vo, include_deleted=True, session=session)
                rse_module.restore_rse(rse_id, session=session)
                selected_rse_properties = {key: rse[key] for key in rse if key in rse_module.MUTABLE_RSE_PROPERTIES}
                rse_module.update_rse(rse_id=rse_id, parameters=selected_rse_properties, session=session)
            else:
                # Config is in RSE append only mode, should not modify the disabled RSE
                continue
        else:
            rse_id = rse_module.add_rse(rse=rse_name, vo=vo, deterministic=rse.get('deterministic'), volatile=rse.get('volatile'),
                                        city=rse.get('city'), region_code=rse.get('region_code'), country_name=rse.get('country_name'),
                                        staging_area=rse.get('staging_area'), continent=rse.get('continent'), time_zone=rse.get('time_zone'),
                                        ISP=rse.get('ISP'), rse_type=rse.get('rse_type'), latitude=rse.get('latitude'),
                                        longitude=rse.get('longitude'), ASN=rse.get('ASN'), availability_read=rse.get('availability_read'),
                                        availability_write=rse.get('availability_write'), availability_delete=rse.get('availability_delete'),
                                        session=session)

        new_rses.append(rse_id)
        # Protocols
        new_protocols = rse.get('protocols')
        if new_protocols:
            # update existing, add missing and remove left over protocols
            old_protocols = [{'scheme': protocol['scheme'], 'hostname': protocol['hostname'], 'port': protocol['port']} for protocol in rse_module.get_rse_protocols(rse_id=rse_id, session=session)['protocols']]
            missing_protocols = [new_protocol for new_protocol in new_protocols if {'scheme': new_protocol['scheme'], 'hostname': new_protocol['hostname'], 'port': new_protocol['port']} not in old_protocols]
            outdated_protocols = [new_protocol for new_protocol in new_protocols if {'scheme': new_protocol['scheme'], 'hostname': new_protocol['hostname'], 'port': new_protocol['port']} in old_protocols]
            new_protocols = [{'scheme': protocol['scheme'], 'hostname': protocol['hostname'], 'port': protocol['port']} for protocol in new_protocols]
            to_be_removed_protocols = [old_protocol for old_protocol in old_protocols if old_protocol not in new_protocols]

            if protocol_sync_method == 'append':
                outdated_protocols = []

            for protocol in outdated_protocols:
                scheme = protocol['scheme']
                port = protocol['port']
                hostname = protocol['hostname']
                del protocol['scheme']
                del protocol['hostname']
                del protocol['port']
                rse_module.update_protocols(rse_id=rse_id, scheme=scheme, data=protocol, hostname=hostname, port=port, session=session)

            for protocol in missing_protocols:
                rse_module.add_protocol(rse_id=rse_id, parameter=protocol, session=session)

            if protocol_sync_method == 'hard':
                for protocol in to_be_removed_protocols:
                    scheme = protocol['scheme']
                    port = protocol['port']
                    hostname = protocol['hostname']
                    rse_module.del_protocols(rse_id=rse_id, scheme=scheme, port=port, hostname=hostname, session=session)

        # Limits
        old_limits = rse_module.get_rse_limits(rse_id=rse_id, session=session)
        for limit_name in ['MinFreeSpace']:
            limit = rse.get(limit_name)
            if limit:
                if limit_name in old_limits:
                    rse_module.delete_rse_limits(rse_id=rse_id, name=limit_name, session=session)
                rse_module.set_rse_limits(rse_id=rse_id, name=limit_name, value=limit, session=session)

        # Attributes
        attributes = rse.get('attributes', {})
        attributes['lfn2pfn_algorithm'] = rse.get('lfn2pfn_algorithm')
        attributes['verify_checksum'] = rse.get('verify_checksum')

        old_attributes = rse_module.list_rse_attributes(rse_id=rse_id, session=session)
        missing_attributes = [attribute for attribute in old_attributes if attribute not in attributes]

        for attr in attributes:
            value = attributes[attr]
            if value is not None:
                if attr in old_attributes:
                    if attr_sync_method not in ['append']:
                        rse_module.del_rse_attribute(rse_id=rse_id, key=attr, session=session)
                        rse_module.add_rse_attribute(rse_id=rse_id, key=attr, value=value, session=session)
                else:
                    rse_module.add_rse_attribute(rse_id=rse_id, key=attr, value=value, session=session)
        if attr_sync_method == 'hard':
            for attr in missing_attributes:
                if attr != rse_name:
                    rse_module.del_rse_attribute(rse_id=rse_id, key=attr, session=session)

    # set deleted flag to RSEs that are missing in the import data
    old_rses = [old_rse['id'] for old_rse in rse_module.list_rses(session=session)]
    if rse_sync_method == 'hard':
        for old_rse in old_rses:
            if old_rse not in new_rses:
                try:
                    rse_module.del_rse(rse_id=old_rse, session=session)
                except RSEOperationNotSupported:
                    pass


@transactional_session
def import_distances(distances, vo='def', *, session: "Session"):
    for src_rse_name in distances:
        src = rse_module.get_rse_id(rse=src_rse_name, vo=vo, session=session)
        for dest_rse_name in distances[src_rse_name]:
            dest = rse_module.get_rse_id(rse=dest_rse_name, vo=vo, session=session)
            distance_dict = distances[src_rse_name][dest_rse_name]
            if 'src_rse_id' in distance_dict:
                del distance_dict['src_rse_id']
            if 'dest_rse_id' in distance_dict:
                del distance_dict['dest_rse_id']

            old_distance = distance_module.get_distances(src_rse_id=src, dest_rse_id=dest, session=session)
            new_distance = distance_dict.get('distance', distance_dict.get('ranking'))
            if old_distance:
                distance_module.update_distances(src_rse_id=src, dest_rse_id=dest, distance=new_distance, session=session)
            else:
                distance_module.add_distance(src_rse_id=src, dest_rse_id=dest, distance=new_distance, session=session)


@transactional_session
def import_identities(identities, account_name, old_identities, old_identity_account, account_email, *, session: "Session"):
    for identity in identities:
        identity['type'] = IdentityType[identity['type'].upper()]

    missing_identities = [identity for identity in identities if (identity['identity'], identity['type']) not in old_identities]
    missing_identity_account = [identity for identity in identities if (identity['identity'], identity['type'], account_name) not in old_identity_account]
    to_be_removed_identity_account = [old_identity for old_identity in old_identity_account if (old_identity[0], old_identity[1], old_identity[2]) not in
                                      [(identity['identity'], identity['type'], account_name) for identity in identities] and old_identity[2] == account_name]

    # add missing identities
    for identity in missing_identities:
        identity_type = identity['type']
        password = identity.get('password')
        identity = identity['identity']
        if identity_type == IdentityType.USERPASS:
            identity_module.add_identity(identity=identity, password=password, email=account_email, type_=identity_type, session=session)
        elif identity_type == IdentityType.GSS or identity_type == IdentityType.SSH or identity_type == IdentityType.X509:
            identity_module.add_identity(identity=identity, email=account_email, type_=identity_type, session=session)

    # add missing identity-account association
    for identity in missing_identity_account:
        identity_module.add_account_identity(identity['identity'], identity['type'], account_name, email=account_email, session=session)

    # remove identities from account-identity association
    for identity in to_be_removed_identity_account:
        identity_module.del_account_identity(identity=identity[0], type_=identity[1], account=identity[2], session=session)


@transactional_session
def import_accounts(accounts, vo='def', *, session: "Session"):
    vo_filter = {'account': InternalAccount(account='*', vo=vo)}
    old_accounts = {account['account']: account for account in account_module.list_accounts(filter_=vo_filter, session=session)}
    missing_accounts = [account for account in accounts if account['account'] not in old_accounts]
    outdated_accounts = [account for account in accounts if account['account'] in old_accounts]
    to_be_removed_accounts = [old_account for old_account in old_accounts if old_account not in [account['account'] for account in accounts]]
    old_identities = identity_module.list_identities(session=session)
    old_identity_account = session.query(models.IdentityAccountAssociation.identity, models.IdentityAccountAssociation.identity_type, models.IdentityAccountAssociation.account).all()

    # add missing accounts
    for account_dict in missing_accounts:
        account = account_dict['account']
        email = account_dict['email']
        account_module.add_account(account=account, type_=AccountType.USER, email=email, session=session)
        identities = account_dict.get('identities', [])
        if identities:
            import_identities(identities, account, old_identities, old_identity_account, email, session=session)

    # remove left over accounts
    for account in to_be_removed_accounts:
        if account.external != 'root':
            account_module.del_account(account=account, session=session)

    # update existing accounts
    for account_dict in outdated_accounts:
        account = account_dict['account']
        email = account_dict['email']
        old_account = old_accounts[account]
        if email and old_account['email'] != email:
            account_module.update_account(account, key='email', value=email, session=session)

        identities = account_dict.get('identities', [])
        if identities:
            import_identities(identities, account, old_identities, old_identity_account, email, session=session)


@transactional_session
def import_data(data, vo='def', *, session: "Session"):
    """
    Import data to add and update records in Rucio.

    :param data: data to be imported as dictionary.
    :param session: database session in use.
    """
    rse_sync_method = config_get('importer', 'rse_sync_method', False, 'edit')
    attr_sync_method = config_get('importer', 'attr_sync_method', False, 'edit')
    protocol_sync_method = config_get('importer', 'rse_sync_method', False, 'edit')

    rses = data.get('rses')
    if rses:
        import_rses(rses, rse_sync_method=rse_sync_method, attr_sync_method=attr_sync_method, protocol_sync_method=protocol_sync_method, vo=vo, session=session)

    # Distances
    distances = data.get('distances')
    if distances:
        import_distances(distances, vo=vo, session=session)

    # Accounts
    accounts = data.get('accounts')
    if accounts:
        import_accounts(accounts, vo=vo, session=session)
