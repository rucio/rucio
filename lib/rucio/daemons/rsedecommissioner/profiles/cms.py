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

"""CMS-specific decommissioning profiles."""

import logging
from typing import TYPE_CHECKING, Any

from sqlalchemy.exc import NoResultFound

from rucio.common.exception import Duplicate, RucioException, InvalidRSEExpression
from rucio.core.lock import get_replica_locks_for_rule_id
from rucio.core.rse import add_rse_attribute
from rucio.core.rse_expression_parser import parse_expression

from . import generic
from .types import DecommissioningProfile, HandlerOutcome

if TYPE_CHECKING:
    from rucio.common.types import LoggerFunction
    
WM_ACCOUNTS = [
    'wma_prod', 'wmccorma', 'wmcore_output', 'wmcore_pileup', 'wmcore_transferor'
]

def cms_decommissioner(rse: dict[str, Any], config: dict[str, Any]) -> DecommissioningProfile:
    """Return a profile for moving rules that satisfy conditions to a specific destination.

    The "CMS decommissioner" profile lists out all rules that are locking replicas
    at the given RSE and acts on them based on the following conditions:

    - Test rules will be deleted.
    - CRAB TapeRecall rules will be skipped. Manual operations are needed.
    - WM rules will be skipped. Manual operations are needed.
    - Rules with trivial RSE expression (the RSE name itself) will be moved to the destination.
    - Rules with complex RSE expression will be moved by excluding the target RSE.

    :param rse: RSE to decommission.
    :param config: Decommissioning configuration dictionary.
    :returns: A decommissioning profile dictionary.
    """
    
    destination = str(config.get('destination', None))
    move_to_destination = CMSRuleMover(destination)
    
    return DecommissioningProfile(
        rse = rse,
        initializer = _cms_initialize,
        discoverer = generic._generic_discover,
        
        handlers = [
            (generic._is_locked, generic._call_for_attention),
            (generic._is_being_deleted, generic._count_as_processed),
            (generic._has_child_rule_id, generic._count_as_processed),
            
            # Rules under 'Functional Test' activity are test rules. These rules can be removed. 
            # Test rules with the underlined RSE as source are not handled! Implementing a dedicated 
            # discoverer to fetch these kind of rules may be possible. However, the existence of them 
            # will not introduce a major problem and if needed operators can act.
            (_is_test_rule, generic._delete_rule),
            
            # Rules under 'Analysis TapeRecall' activity are created with users' accounts using CRAB.
            # These rules need operators attention. Operators should inform CRAB before take any action.
            # Rules under 'Analysis Input' are created with the 'crab_input' account and can be handled 
            # as any other rule
            (_is_crab_taperecall_rule, generic._call_for_attention),
            
            # Moving rules created by WM account could cause operational and monitoring issues in DM
            # and WM. WM uses rules ids to track rules and delete them when certain conditions are made.
            # Moving rules will result in a different rule id that WM is not aware of. Best way to 
            # handle these rules is to wait for their expiration.
            (_is_wm_rule, generic._call_for_attention),
            
            # Every other rule should moved.
            (_has_replicas_on_rse, move_to_destination)
        ],
        
        # TODO: should moc protocol be added ? (introduced since 2020 by OscarFernandoGarzonMiguez)
        # https://twiki.cern.ch/twiki/bin/view/CMSPublic/RseConfiguration#Decommissioning_Procedure
        # TODO: should rse be deleted ?
        finalizer = generic._generic_finalize
    )

def _cms_initialize(
    rse: dict[str, Any],
    *,
    logger: "LoggerFunction" = logging.log,
) -> None:
    """Initializer function that sets the RSE availability flags and the decommissioning status.

    When an RSE is initialized for decommissioning, the availability flags are set as follows:

    - `availability_read=True`
    - `availability_write=False`
    - `availability_delete=True`

    and the following attributes are set:

    - 'update_from_json=False'
    - `skip_site_availability_update=True`
    - `loadtest=False`
    - `greedyDeletion=True`

    :param rse: RSE table entry as a dictionary.
    :param logger: Logging function.
    """
    logger(logging.INFO,
        '(%s) Setting update_from_json=false.',
        rse['rse'])
    
    try:
        add_rse_attribute(rse['id'], 'update_from_json', False)
    except Duplicate:
        pass
    
    logger(logging.INFO,
        '(%s) Setting loadtest=false.',
        rse['rse'])
    
    try:
        add_rse_attribute(rse['id'], 'loadtest', False)
    except Duplicate:
        pass
    
    logger(logging.INFO,
           '(%s) Setting skip_site_availability_update=true.',
           rse['rse'])
    
    try:
        add_rse_attribute(rse['id'], 'skip_site_availability_update', True)
    except Duplicate:
        pass
    
    generic._generic_initialize(rse)
    
    logger(logging.INFO,
        '(%s) Setting reaper=true.',
        rse['rse'])
    
    try:
        add_rse_attribute(rse['id'], 'reaper', True)
    except Duplicate:
        pass
    
def _is_test_rule(
    rule: dict[str, Any],
    rse: dict[str, Any],
    *,
    logger: "LoggerFunction" = logging.log
) -> bool:
    """Check if test rule (rse is the destination only)."""
    return rule['activity'] == 'Functional Test'

def _is_crab_taperecall_rule(
    rule: dict[str, Any],
    rse: dict[str, Any],
    *,
    logger: "LoggerFunction" = logging.log
) -> bool:
    """Check if rule's activity is 'Analysis TapeRecall'"""
    return rule['activity'] == 'Analysis TapeRecall'

def _is_wm_rule(
    rule: dict[str, Any],
    rse: dict[str, Any],
    *,
    logger: "LoggerFunction" = logging.log
) -> bool:
    """Check if rule's activity is 'Analysis TapeRecall'"""
    return rule['account'] in WM_ACCOUNTS

def _has_replicas_on_rse(
    rule: dict[str, Any],
    rse: dict[str, Any],
    *,
    logger: "LoggerFunction" = logging.log
) -> bool:
    """Check if there are replicas on the RSE."""
    # Check the list of RSEs that the replicas locked by this rule reside on.
    try:
        locks = get_replica_locks_for_rule_id(rule['id'])
    except NoResultFound:
        # No replica is locked to begin with -> treat as having the last replica on this RSE
        return True

    replica_rse_ids = set(lock['rse_id'] for lock in locks)

    return rse['id'] in replica_rse_ids

def _has_trivial_rse_expression(
    rule: dict[str, Any],
    rse: dict[str, Any],
    *,
    logger: "LoggerFunction" = logging.log
) -> bool:
    """Check for a trivial rse_expression."""
    return (rule['rse_expression'] == rse['rse']) or rule['rse_expression'] == f"rse={rse['rse']}"
    
class CMSRuleMover(generic.RuleMover):
    """RuleMover with dynamic destination logic for CMS-specific rules."""

    def __call__(
        self,
        rule: dict[str, Any],
        rse: dict[str, Any],
        *,
        logger: "LoggerFunction" = logging.log
    ) -> HandlerOutcome:
        """Move the rule after dynamically resolving the destination."""
        logger(logging.DEBUG, '(%s) Preparing to move rule %s', rse['rse'], rule['id'])

        if not self._update_destination(rule, rse, logger=logger):
            logger(logging.INFO,
                   '(%s) Cannot safely move rule %s. Calling for operator attention.',
                   rse['rse'], rule['id'])
            return HandlerOutcome.NEED_ATTENTION

        return super().__call__(rule, rse, logger=logger)

    def _update_destination(
        self,
        rule: dict[str, Any],
        rse: dict[str, Any],
        *,
        logger: "LoggerFunction"
    ) -> bool:
        """Update the destination based on rule and RSE conditions.
        Returns True if destination is valid; False if operator attention is needed.
        """
        if not _has_trivial_rse_expression(rule, rse):
            combined_expr = f"{rule['rse_expression']}\\{rse['rse']}"
            resolved_rses = parse_expression(combined_expr)
            required_copies = rule['copies']
            if len(resolved_rses) < required_copies:
                logger(logging.WARNING,
                       'Expression "%s" resolves to %d RSE(s), but %d copies are required.',
                       combined_expr, len(resolved_rses), required_copies)
                return False
            
            self.destination = combined_expr
        else:
            if self.destination == str(None):
                logger(logging.WARNING,
                       'No default destination set for trivial RSE expression on rule %s',
                       rule['id'])
                return False

        return True
