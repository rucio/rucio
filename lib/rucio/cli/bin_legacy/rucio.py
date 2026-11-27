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


@click.group(hidden=True)
def rucio_main_legacy():
    pass


@rucio_main_legacy.command("list-dataset-replicas", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def list_dataset_replicas():
    print("Command 'list-dataset-replicas' has been removed; please see 'rucio replica --help'")


@rucio_main_legacy.command("list-file-replicas", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def list_file_replicas():
    print("Command 'list-file-replicas' has been removed; please see 'rucio replica --help'")


@rucio_main_legacy.command("add-dataset", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def add_dataset():
    print("Command 'add-dataset' has been removed; please see 'rucio did --help'")


@rucio_main_legacy.command("add-container", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def add_container():
    print("Command 'add-container' has been removed; please see 'rucio did --help'")


@rucio_main_legacy.command("attach", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def attach():
    print("Command 'attach' has been removed; please see 'rucio did --help'")


@rucio_main_legacy.command("detach", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def detach():
    print("Command 'detach' has been removed; please see 'rucio did --help'")


@rucio_main_legacy.command("ls", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def ls():
    print("Command 'ls' has been removed; please see 'rucio did --help'")


@rucio_main_legacy.command("list-dids", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def list_dids():
    print("Command 'list-dids' has been removed; please see 'rucio did --help'")


@rucio_main_legacy.command("list-dids-extended", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def list_dids_extended():
    print("Command 'list-dids-extended' has been removed; please see 'rucio did --help'")


@rucio_main_legacy.command("list-scopes", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def list_scopes():
    print("Command 'list-scopes' has been removed; please see 'rucio scope --help'")


@rucio_main_legacy.command("list-files", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def list_files():
    print("Command 'list-files' has been removed; please see 'rucio did --help'")


@rucio_main_legacy.command("list-content", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def list_content():
    print("Command 'list-content' has been removed; please see 'rucio did --help'")


@rucio_main_legacy.command("list-content-history", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def list_content_history():
    print("Command 'list-content-history' has been removed; please see 'rucio did --help'")


@rucio_main_legacy.command("list-parent-dids", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def list_parent_dids():
    print("Command 'list-parent-dids' has been removed; please see 'rucio did --help'")


@rucio_main_legacy.command("list-parent-datasets", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def list_parent_datasets():
    print("Command 'list-parent-datasets' has been removed; please see 'rucio did --help'")


@rucio_main_legacy.command("close", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def close():
    print("Command 'close' has been removed; please see 'rucio did --help'")


@rucio_main_legacy.command("reopen", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def reopen():
    print("Command 'reopen' has been removed; please see 'rucio did --help'")


@rucio_main_legacy.command("stat", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def stat():
    print("Command 'stat' has been removed; please see 'rucio did --help'")


@rucio_main_legacy.command("erase", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def erase():
    print("Command 'erase' has been removed; please see 'rucio did --help'")


@rucio_main_legacy.command("get-metadata", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def get_metadata():
    print("Command 'get-metadata' has been removed; please see 'rucio did --help'")


@rucio_main_legacy.command("set-metadata", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def set_metadata():
    print("Command 'set-metadata' has been removed; please see 'rucio did --help'")


@rucio_main_legacy.command("delete-metadata", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def delete_metadata():
    print("Command 'delete-metadata' has been removed; please see 'rucio did --help'")


@rucio_main_legacy.command("add-rule", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def add_rule():
    print("Command 'add-rule' has been removed; please see 'rucio rule --help'")


@rucio_main_legacy.command("delete-rule", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def delete_rule():
    print("Command 'delete-rule' has been removed; please see 'rucio rule --help'")


@rucio_main_legacy.command("update-rule", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def update_rule():
    print("Command 'update-rule' has been removed; please see 'rucio rule --help'")


@rucio_main_legacy.command("move-rule", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def move_rule():
    print("Command 'move-rule' has been removed; please see 'rucio rule --help'")


@rucio_main_legacy.command("rule-info", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def info_rule():
    print("Command 'rule-info' has been removed; please see 'rucio rule --help'")


@rucio_main_legacy.command("list-rules", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def list_rules():
    print("Command 'list-rules' has been removed; please see 'rucio rule --help'")


@rucio_main_legacy.command("list-rules-history", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def list_rules_history():
    print("Command 'list-rules-history' has been removed; please see 'rucio rule --help'")


@rucio_main_legacy.command("list-rses", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def list_rses():
    print("Command 'list-rses' has been removed; please see 'rucio rse --help'")


@rucio_main_legacy.command("list-suspicious-replicas", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def list_suspicious_replicas():
    print("Command 'list-suspicious-replicas' has been removed; please see 'rucio replica --help'")


@rucio_main_legacy.command("list-rse-attributes", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def list_rse_attributes():
    print("Command 'list-rse-attributes' has been removed; please see 'rucio rse --help'")


@rucio_main_legacy.command("list-rse-usage", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def list_rse_usage():
    print("Command 'list-rse-usage' has been removed; please see 'rucio rse --help'")


@rucio_main_legacy.command("list-account-limits", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def list_account_limits():
    print("Command 'list-account-limits' has been removed; please see 'rucio account --help'")


@rucio_main_legacy.command("list-account-usage", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def list_account_usage():
    print("Command 'list-account-usage' has been removed; please see 'rucio account --help'")


@rucio_main_legacy.command("list-datasets-rse", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def list_datasets_rse():
    print("Command 'list-datasets-rse' has been removed; please see 'rucio replica --help'")


@rucio_main_legacy.command("add-lifetime-exception", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def add_lifetime_exception():
    print("Command 'add-lifetime-exception' has been removed; please see 'rucio lifetime-exception --help'")


@rucio_main_legacy.command("touch", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def touch():
    print("Command 'touch' has been removed; please see 'rucio did --help'")


@rucio_main_legacy.command("get", hidden=True, context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def get():
    print("Command 'get' has been removed; please see 'rucio download --help'")
