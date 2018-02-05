''' Copyright European Organization for Nuclear Research (CERN)
 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Brian Bockelman, <bbockelm@cse.unl.edu>, 2019
'''

from rucio.rse.protocols.protocol import RSEDeterministicTranslation


def lfn2pfn_module_algorithm(scope, name, rse, rse_attributes, protocol_attributes):
    """Dummy LFN2PFN algorithm for unit tests."""
    del scope
    del name
    del rse
    del rse_attributes
    del protocol_attributes
    return "lfn2pfn_module_algorithm_value"


RSEDeterministicTranslation.register(lfn2pfn_module_algorithm)
