# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

from rucio.rse import rsemanager
from rucio.common import config


if config.config_has_section('database'):
    setattr(rsemanager, 'CLIENT_MODE', False)
    setattr(rsemanager, 'SERVER_MODE', True)
elif config.config_has_section('client'):
    setattr(rsemanager, 'CLIENT_MODE', True)
    setattr(rsemanager, 'SERVER_MODE', False)
else:
    setattr(rsemanager, 'CLIENT_MODE', False)
    setattr(rsemanager, 'SERVER_MODE', True)


def get_rse_client(rse, **kwarg):
    from rucio.client.rseclient import RSEClient
    return RSEClient().get_rse(rse)


if rsemanager.CLIENT_MODE:
    setattr(rsemanager, '__request_rse_info', get_rse_client)


if rsemanager.SERVER_MODE:
    from rucio.core.rse import get_rse_protocols
    setattr(rsemanager, '__request_rse_info', get_rse_protocols)
