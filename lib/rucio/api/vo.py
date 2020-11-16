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
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Mario Lassnig <mario.lassnig@cern.ch>, 2020

from rucio.api.permission import has_permission
from rucio.common import exception
from rucio.common.schema import validate_schema
from rucio.common.types import InternalAccount
from rucio.core import identity
from rucio.core import vo as vo_core
from rucio.db.sqla.constants import IdentityType


def add_vo(new_vo, issuer, description=None, email=None, vo='def'):
    '''
    Add a new VO.

    :param new_vo: The name/tag of the VO to add (3 characters).
    :param description: A description of the VO. e.g the full name or a brief description
    :param email: A contact for the VO.
    :param issuer: The user issuing the command.
    :param vo: The vo of the user issuing the command.
    '''

    validate_schema('vo', new_vo, vo=vo)

    kwargs = {}
    if not has_permission(issuer=issuer, action='add_vo', kwargs=kwargs, vo=vo):
        raise exception.AccessDenied('Account {} cannot add a VO'.format(issuer))

    vo_core.add_vo(vo=new_vo, description=description, email=email)


def list_vos(issuer, vo='def'):
    '''
    List the VOs.

    :param issuer: The user issuing the command.
    :param vo: The vo of the user issuing the command.
    '''
    kwargs = {}
    if not has_permission(issuer=issuer, action='list_vos', kwargs=kwargs, vo=vo):
        raise exception.AccessDenied('Account {} cannot list VOs'.format(issuer))

    return vo_core.list_vos()


def recover_vo_root_identity(root_vo, identity_key, id_type, email, issuer, default=False, password=None, vo='def'):
    """
    Adds a membership association between identity and the root account for given VO.

    :param root_vo: The VO whose root needs recovery
    :param identity_key: The identity key name. For example x509 DN, or a username.
    :param id_type: The type of the authentication (x509, gss, userpass, ssh, saml).
    :param email: The Email address associated with the identity.
    :param issuer: The issuer account.
    :param default: If True, the account should be used by default with the provided identity.
    :param password: Password if id_type is userpass.
    :param vo: the VO to act on.
    """
    kwargs = {}
    if not has_permission(issuer=issuer, vo=vo, action='recover_vo_root_identity', kwargs=kwargs):
        raise exception.AccessDenied('Account %s can not recover root identity' % (issuer))

    account = InternalAccount('root', vo=root_vo)

    return identity.add_account_identity(identity=identity_key, type=IdentityType[id_type.upper()], default=default, email=email, account=account, password=password)


def update_vo(updated_vo, parameters, issuer, vo='def'):
    """
    Update VO properties (email, description).

    :param updated_vo: The VO to update.
    :param parameters: A dictionary with the new properties.
    :param issuer: The user issuing the command.
    :param vo: The VO of the user issusing the command.
    """
    kwargs = {}
    if not has_permission(issuer=issuer, action='update_vo', kwargs=kwargs, vo=vo):
        raise exception.AccessDenied('Account {} cannot update VO'.format(issuer))

    return vo_core.update_vo(vo=updated_vo, parameters=parameters)
