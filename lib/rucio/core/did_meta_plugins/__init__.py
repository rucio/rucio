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

import importlib
from configparser import NoOptionError, NoSectionError
from typing import TYPE_CHECKING

from rucio.common import config, exception
from rucio.db.sqla.session import read_session, transactional_session

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

# Set default modules.
#
# - "base" metadata is tied to column fields in the "dids" table. As such, types are restricted to column types and
#   additional fields cannot be created.
# - "custom" metadata refers to any plugin that has been written to interface with Rucio's metadata plugin system.
#
# By default, the default custom metadata plugin is set to the prepackaged json module. This utilises a separate table,
# "did_meta", allowing users to add custom metadata key/value pairs of any type.
#
DEFAULT_BASE_METADATA_PLUGIN_MODULE_PATH = "rucio.core.did_meta_plugins.did_column_meta.DidColumnMeta"
DEFAULT_CUSTOM_METADATA_PLUGIN_MODULE_PATH = "rucio.core.did_meta_plugins.json_meta.JSONDidMeta"

# Overwrite these defaults if plugins are set in the configuration file.
#
if config.config_has_section('metadata'):
    try:
        CUSTOM_METADATA_PLUGIN_MODULE_PATHS = config.config_get('metadata', 'plugins')
    except (NoOptionError, NoSectionError):
        CUSTOM_METADATA_PLUGIN_MODULE_PATHS = DEFAULT_CUSTOM_METADATA_PLUGIN_MODULE_PATH
else:
    CUSTOM_METADATA_PLUGIN_MODULE_PATHS = DEFAULT_CUSTOM_METADATA_PLUGIN_MODULE_PATH
METADATA_PLUGIN_MODULE_PATHS = [DEFAULT_BASE_METADATA_PLUGIN_MODULE_PATH] + CUSTOM_METADATA_PLUGIN_MODULE_PATHS.split(",")

# Import plugin modules.
#
# Note that the order of this list is important. As the base metadata plugin module is always first, base key
# retrieval and setting will always take precedence over custom plugins, i.e. it is not possible to set a custom key with
# the same name as those in the base list.
#
# Another consequence of this is that if set_metadata() is called with multiple plugins specified, the first to return
# True to manages_key() will be used.
#
METADATA_PLUGIN_MODULES = []
for meta_module_path in METADATA_PLUGIN_MODULE_PATHS:
    try:
        base_module = ".".join(meta_module_path.split(".")[:-1])
        base_class = meta_module_path.split(".")[-1]
        metadata_plugin_module = getattr(importlib.import_module(base_module), base_class)()
        METADATA_PLUGIN_MODULES.append(metadata_plugin_module)
    except ImportError:
        raise exception.PolicyPackageNotFound('Module ' + meta_module_path + ' not found')

# Set restricted character set for metadata in form character: reason
#
RESTRICTED_CHARACTERS = {
    '.': "Used as a delimiter for key and operator (<key>.<operator>) in filtering engine."
}


@read_session
def get_metadata(scope, name, plugin="DID_COLUMN", *, session: "Session"):
    """
    Gets the metadata for a given did from a specified plugin.

    If [plugin] is set to "all", metadata from all available metadata plugins will be returned,
    else [plugin] can be used to only return the metadata using a specific plugin.

    :param scope: The scope of the did.
    :param name: The data identifier name.
    :param plugin: (optional) Filter specific metadata plugins.
    :returns: List of metadata for did.
    :raises: NotImplementedError
    """
    if plugin.lower() == "all":
        all_metadata = {}
        for metadata_plugin in METADATA_PLUGIN_MODULES:
            metadata = metadata_plugin.get_metadata(scope, name, session=session)
            all_metadata.update(metadata)
        return all_metadata
    else:
        for metadata_plugin in METADATA_PLUGIN_MODULES:
            if metadata_plugin.get_plugin_name().lower() == plugin.lower():
                return metadata_plugin.get_metadata(scope, name, session=session)
    raise NotImplementedError('Metadata plugin "%s" is not enabled on the server.' % plugin)


@transactional_session
def set_metadata(scope, name, key, value, recursive=False, *, session: "Session"):
    """
    Sets metadata for a given did.

    :param scope: The scope of the did.
    :param name: The data identifier name.
    :param key: Metadata key.
    :param value: Metadata value.
    :param recursive: (optional) Propagate the metadata change recursively to content.
    :param session: (optional) The database session in use.
    :raises: InvalidMetadata
    """
    # Check for forbidden characters in key.
    for char in RESTRICTED_CHARACTERS:
        if char in key:
            raise exception.InvalidMetadata('Restricted character "{}" found in metadata key. Reason: {}'.format(
                char,
                RESTRICTED_CHARACTERS[char]
            ))

    # Sequentially check if each metadata plugin manages this key. Note that the order of [METADATA_PLUGIN_MODULES]
    # means that the key is always checked for existence in the base list first.
    metadata_was_set = False
    for metadata_plugin in METADATA_PLUGIN_MODULES:
        if metadata_plugin.manages_key(key, session=session):
            metadata_plugin.set_metadata(scope, name, key, value, recursive, session=session)
            metadata_was_set = True
            break

    if not metadata_was_set:
        raise exception.InvalidMetadata('No plugin manages metadata key %s for DID %s:%s' % (key, scope, name))


@transactional_session
def set_metadata_bulk(scope, name, meta, recursive=False, *, session: "Session"):
    """
    Bulk sets metadata for a given did.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param meta: The key-value mapping of metadata to set.
    :param recursive: (optional) Propagate the metadata change recursively to content.
    :param session: (optional) The database session in use.
    :raises: InvalidMetadata
    """
    metadata = meta

    unmanaged_keys = list()
    if not isinstance(metadata, dict):
        metadata = dict(metadata)
    metadata_plugin_keys = {metadata_plugin: [] for metadata_plugin in METADATA_PLUGIN_MODULES}

    # Iterate through all keys, sequentially checking if each metadata plugin manages the considered key. If it
    # does, add it to the list in the plugin's entry in {metadata_plugin_keys}. Note that the order of
    # [METADATA_PLUGIN_MODULES] means that the key is always checked for existence in the base list first.
    for key in metadata.keys():
        # Check for forbidden characters in key.
        for char in RESTRICTED_CHARACTERS:
            if char in key:
                raise exception.InvalidMetadata('Restricted character "{}" found in metadata key. Reason: {}'.format(
                    char,
                    RESTRICTED_CHARACTERS[char]
                ))
        metadata_is_included = False
        for metadata_plugin in METADATA_PLUGIN_MODULES:
            if metadata_plugin.manages_key(key, session=session):
                metadata_plugin_keys[metadata_plugin].append(key)
                metadata_is_included = True
                break
        if not metadata_is_included:
            unmanaged_keys.append(key)
    if unmanaged_keys:
        raise exception.InvalidMetadata('No plugin manages metadata keys %s on DID %s:%s' % (unmanaged_keys, scope, name))

    # For each plugin, set the metadata.
    for metadata_plugin, keys_managed_by_this_plugin in metadata_plugin_keys.items():
        if keys_managed_by_this_plugin:
            this_plugin_metadata = {key: metadata[key] for key in keys_managed_by_this_plugin}
            metadata_plugin.set_metadata_bulk(scope, name, metadata=this_plugin_metadata, recursive=recursive, session=session)


@transactional_session
def delete_metadata(scope, name, key, *, session: "Session"):
    """
    Deletes metadata stored for a given key.

    :param scope: The scope of the did.
    :param name: The name of the did.
    :param key: Key of the metadata.
    """
    for metadata_plugin in METADATA_PLUGIN_MODULES:
        if metadata_plugin.manages_key(key, session=session):
            metadata_plugin.delete_metadata(scope, name, key, session=session)


@read_session
def list_dids(scope=None, filters=None, did_type='collection', ignore_case=False, limit=None,
              offset=None, long=False, recursive=False, ignore_dids=None, *, session: "Session"):
    """
    Search data identifiers.

    All filter keys should belong to a single plugin. Queries across plugins are not currently supported.

    :param scope: the scope name.
    :param filters: dictionary of attributes by which the results should be filtered.
    :param did_type: the type of the did: all(container, dataset, file), collection(dataset or container), dataset, container, file.
    :param ignore_case: ignore case distinctions.
    :param limit: limit number.
    :param offset: offset number.
    :param long: Long format option to display more information for each DID.
    :param recursive: Recursively list DIDs content.
    :param ignore_dids: List of DIDs to refrain from yielding.
    :param session: The database session in use.
    :returns: List of dids satisfying metadata criteria.
    :raises: InvalidMetadata
    """
    # backwards compatability for filters as single {}.
    if isinstance(filters, dict):
        filters = [filters]

    required_unique_plugins = set()                 # keep track of which plugins are required
    for or_group in filters:
        for key in or_group.keys():
            if key == 'name':                       # [name] is always passed through, and needs to be in schema of all plugins
                continue
            key_nooperator = key.split('.')[0]      # remove operator attribute from key if suffixed

            # Iterate through the list of metadata plugins, checking which (if any) manages this particular key
            # and appending the corresponding plugin to the set, required_unique_plugins.
            is_this_key_managed = False
            for metadata_plugin in METADATA_PLUGIN_MODULES:
                if metadata_plugin.manages_key(key_nooperator, session=session):
                    required_unique_plugins.add(metadata_plugin)
                    is_this_key_managed = True
                    break
            if not is_this_key_managed:
                raise exception.InvalidMetadata('There is no metadata plugin that manages the filter key(s) you requested.')

    if not required_unique_plugins:               # if no metadata keys were specified, fall back to using the base plugin
        required_unique_plugins = [METADATA_PLUGIN_MODULES[0]]
    elif len(required_unique_plugins) > 1:        # check that only a single plugin is required for the query, otherwise not supported
        raise exception.InvalidMetadata('Filter keys used do not all belong to the same metadata plugin.')
    selected_plugin_to_use = list(required_unique_plugins)[0]

    return selected_plugin_to_use.list_dids(scope=scope, filters=filters, did_type=did_type,
                                            ignore_case=ignore_case, limit=limit,
                                            offset=offset, long=long, recursive=recursive,
                                            ignore_dids=ignore_dids, session=session)
