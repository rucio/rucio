#!/usr/bin/env python
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


import click


@click.group()
def rucio_admin_main():
    pass


# ACCOUNT GROUP ######################
@rucio_admin_main.group("account", hidden=True)
def account():
    pass


@account.command("add", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def add_account():
    print("Command 'account add' has been removed; please see 'rucio account --help'")


@account.command("delete", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def delete_account():
    print("Command 'account delete' has been removed; please see 'rucio account --help'")


@account.command("update", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def update_account():
    print("Command 'account update' has been removed; please see 'rucio account --help'")


@account.command("ban", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def ban_account():
    print("Command 'account ban' has been removed; please see 'rucio account --help'")


@account.command("unban", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def unban_account():
    print("Command 'account unban' has been removed; please see 'rucio account --help'")


@account.command("list", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def list_accounts():
    print("Command 'account list' has been removed; please see 'rucio account --help'")


@account.command("info", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def info_accounts():
    print("Command 'account info' has been removed; please see 'rucio account --help'")


@account.command("set-limits", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def set_limits():
    print("Command 'account set-limits' has been removed; please see 'rucio account --help'")


@account.command("get-limits", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def get_limits():
    print("Command 'account get-limits' has been removed; please see 'rucio account --help'")


@account.command("delete-limits", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def delete_limits():
    print("Command 'account delete-limits' has been removed; please see 'rucio account --help'")


@account.command("list-attributes", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def list_account_attributes():
    print("Command 'account list-attributes' has been removed; please see 'rucio account --help'")


@account.command("add-attribute", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def add_account_attribute():
    print("Command 'account add-attribute' has been removed; please see 'rucio account --help'")


@account.command("delete-attribute", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def delete_account_attribute():
    print("Command 'account delete-attribute' has been removed; please see 'rucio account --help'")


@account.command("list-identities", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def list_ids():
    print("Command 'account list-identities' has been removed; please see 'rucio account --help'")


# ID GROUP ######################
@rucio_admin_main.group("identity", hidden=True)
def id():
    pass


@id.command("list", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def list_identities():
    print("Command 'identity list' has been removed; please see 'rucio account identity --help'")


@id.command("add", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def identity_add():
    print("Command 'identity add' has been removed; please see 'rucio account identity --help'")


@id.command("delete", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def identity_delete():
    print("Command 'identity delete' has been removed; please see 'rucio account identity --help'")


# RSE GROUP ######################
@rucio_admin_main.group("rse", hidden=True)
def rse():
    pass


@rse.command("add", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def add_rse():
    print("Command 'rse add' has been removed; please see 'rucio rse --help'")


@rse.command("delete", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def disable_rse():
    print("Command 'rse delete' has been removed; please see 'rucio rse --help'")


@rse.command("list", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def list_rses():
    print("Command 'rse list' has been removed; please see 'rucio rse --help'")


@rse.command("update", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def update_rse():
    print("Command 'rse update' has been removed; please see 'rucio rse --help'")


@rse.command("info", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def info_rse():
    print("Command 'rse info' has been removed; please see 'rucio rse --help'")


@rse.command("set-attribute", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def set_attribute_rse():
    print("Command 'rse set-attribute' has been removed; please see 'rucio rse --help'")


@rse.command("get-attribute", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def get_attribute_rse():
    print("Command 'rse get-attribute' has been removed; please see 'rucio rse --help'")


@rse.command("delete-attribute", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def delete_attribute_rse():
    print("Command 'rse delete-attribute' has been removed; please see 'rucio rse --help'")


@rse.command("add-distance", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def add_distance_rses():
    print("Command 'rse add-distance' has been removed; please see 'rucio rse --help'")


@rse.command("get-distance", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def get_distance_rses():
    print("Command 'rse get-distance' has been removed; please see 'rucio rse --help'")


@rse.command("update-distance", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def update_distance_rses():
    print("Command 'rse update-distance' has been removed; please see 'rucio rse --help'")


@rse.command("delete-distance", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def delete_distance_rses():
    print("Command 'rse delete-distance' has been removed; please see 'rucio rse --help'")


@rse.command("add-protocol", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def add_protocol_rse():
    print("Command 'rse add-protocol' has been removed; please see 'rucio rse --help'")


@rse.command("delete-protocol", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def del_protocol_rse():
    print("Command 'rse delete-protocol' has been removed; please see 'rucio rse --help'")


@rse.command("set-limit", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def set_limit_rse():
    print("Command 'rse set-limit' has been removed; please see 'rucio rse --help'")


@rse.command("delete-limit", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def delete_limit_rse():
    print("Command 'rse delete-limit' has been removed; please see 'rucio rse --help'")


# SCOPE GROUP ######################
@rucio_admin_main.group("scope", hidden=True)
def scope():
    pass


@scope.command("add", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def add_scope():
    print("Command 'scope add' has been removed; please see 'rucio scope --help'")


@scope.command("list", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def list_scopes():
    print("Command 'scope list' has been removed; please see 'rucio scope --help'")


# CONFIG GROUP ######################
@rucio_admin_main.group("config", hidden=True)
def config():
    pass


@config.command("get", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def get_config():
    print("Command 'config get' has been removed; please see 'rucio config --help'")


@config.command("set", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def set_config_option():
    print("Command 'config set' has been removed; please see 'rucio config --help'")


@config.command("delete", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def delete_config_option():
    print("Command 'config delete' has been removed; please see 'rucio config --help'")


# SUBSCRIPTION GROUP ######################
@rucio_admin_main.group("subscription", hidden=True)
def subscription():
    pass


@subscription.command("add", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def add_subscription():
    print("Command 'subscription add' has been removed; please see 'rucio subscription --help'")


@subscription.command("list", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def list_subscriptions():
    print("Command 'subscription list' has been removed; please see 'rucio subscription --help'")


@subscription.command("update", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def update_subscription():
    print("Command 'subscription update' has been removed; please see 'rucio subscription --help'")


@subscription.command("reevaluate", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def reevaluate_did_for_subscription():
    print("Command 'subscription reevaluate' has been removed; please see 'rucio subscription --help'")


# REPLICAS GROUP ######################
@rucio_admin_main.group("replicas", hidden=True)
def replica():
    pass


@replica.command("quarantine", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def quarantine_replicas():
    print("Command 'replicas quarantine' has been removed; please see 'rucio replica --help'")


@replica.command("declare-bad", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def declare_bad_file_replicas():
    print("Command 'replicas declare-bad' has been removed; please see 'rucio replica --help'")


@replica.command("declare-temporary-unavailable", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def declare_temporary_unavailable_replicas():
    print("Command 'replicas declare-temporary-unavailable' has been removed; please see 'rucio replica --help'")


@replica.command("set-tombstone", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def set_tombstone():
    print("Command 'replicas set-tombstone' has been removed; please see 'rucio replica --help'")


@replica.command("list-pfns", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def list_pfns():
    print("Command 'replicas list-pfns' has been removed; please see 'rucio replica --help'")


# DATA GROUP ######################
@rucio_admin_main.group("data", hidden=True)
def data():
    pass


@data.command("import", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def import_data():
    print("Command 'data import' has been removed; please see 'rucio --help'")


@data.command("export", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def export_data():
    print("Command 'data import' has been removed; please see 'rucio --help'")
