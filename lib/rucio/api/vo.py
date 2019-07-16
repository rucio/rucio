# Copyright 2019 CERN for the benefit of the ATLAS collaboration.
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


from rucio.api.permission import has_permission
from rucio.common import exception
from rucio.common.schema import validate_schema
from rucio.core import vo as vo_core


def add_vo(new_vo, issuer, description=None, email=None, vo='def'):
    '''
    Add a new VO.

    :param new_vo: The name/tag of the VO to add (3 characters).
    :param description: A description of the VO. e.g the full name or a brief description
    :param email: A contact for the VO.
    :param issuer: The user issuing the command.
    :param vo: The vo of the user issuing the command.
    '''

    validate_schema('vo', new_vo)

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
