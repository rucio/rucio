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
__RCSID__ = "$Id$"

import DIRAC
from DIRAC import gLogger
from DIRAC.ConfigurationSystem.Client.CSAPI import CSAPI
from DIRAC.Core.Base import Script
from diraccfg import CFG

Script.parseCommandLine()

args = Script.getPositionalArgs()

if len(args) == 1:
    config_file = args[0]
else:
    gLogger.error("Needs 1 argument: configuration file")
    DIRAC.exit(-1)

cs_api = CSAPI()
cfg = CFG()

cfg.loadFromFile(config_file)

res = cs_api.mergeWithCFG(cfg)
if not res["OK"]:
    gLogger.error("Can't merge with input configuration", f"{res['Message']}")
    DIRAC.exit(-1)

res = cs_api.commit()
if not res["OK"]:
    gLogger.error("Can't commit new configuration data", f"{res['Message']}")
    DIRAC.exit(-1)
