# -*- coding: utf-8 -*-
# Copyright 2020-2021 CERN
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
# - Aristeidis Fkiaras <aristeidis.fkiaras@cern.ch>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Rob Barnsley <rob.barnsley@skao.int>, 2021

import importlib

from rucio.common import config, exception
from rucio.db.sqla.session import read_session

try:
    from ConfigParser import NoOptionError, NoSectionError
except ImportError:
    from configparser import NoOptionError, NoSectionError

# Set default modules.
#
# - Hardcoded metadata is tied to column fields in the "dids" table. As such, types are restricted to column types and 
#   additional fields cannot be created.
# - Custom metadata refers to any plugin that has been written to interface with Rucio's metadata plugin system.
# 
# By default, the custom metadata plugin is set to the prepackaged json module. This utilises a separate table, 
# "did_meta", allowing users to add custom metadata key/value pairs of any type.
#
HARDCODED_METADATA_PLUGIN_MODULE_PATH = "rucio.core.did_meta_plugins.did_column_meta.DidColumnMeta"
FALLBACK_CUSTOM_METADATA_PLUGIN_MODULE_PATH = "rucio.core.did_meta_plugins.json_meta.JSONDidMeta"

# Overwrite these defaults if plugins are set in the configuration file.
#
if config.config_has_section('metadata'):
    try:
        CUSTOM_METADATA_PLUGIN_MODULE_PATHS = config.config_get('metadata', 'plugins')
    except (NoOptionError, NoSectionError):
        CUSTOM_METADATA_PLUGIN_MODULE_PATHS = FALLBACK_CUSTOM_METADATA_PLUGIN_MODULE_PATH
else:
    CUSTOM_METADATA_PLUGIN_MODULE_PATHS = FALLBACK_CUSTOM_METADATA_PLUGIN_MODULE_PATH

METADATA_PLUGIN_MODULE_PATHS = [HARDCODED_METADATA_PLUGIN_MODULE_PATH] + CUSTOM_METADATA_PLUGIN_MODULE_PATHS.split(",")

# Build a list of available plugin modules.
#
# Note that the order of this list is important. As the hardcoded metadata plugin module is always first, hardcoded key 
# retrieval and setting will always take precedence over custom plugins, i.e. it is not possible to set a custom key with 
# the same name as those in the hardcoded list.
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


def get_metadata(scope, name, plugin="DID_COLUMN", session=None):
    """
    Gets the metadata for given did.

    This method retrieves metadata using different metadata plugins.

    If [plugin] is set to "all", metadata from all available metadata plugins will be returned, 
    else [plugin] can be used to only return the metadata using a specific plugin.

    :param scope: The scope of the did.
    :param name: The data identifier name.
    :param plugin: (optional) Filter specific metadata plugins.

    :returns: List of metadata for did.
    """
    if plugin.lower() == "all":
        all_metadata= {}
        for metadata_plugin in METADATA_PLUGIN_MODULES:
            metadata = metadata_plugin.get_metadata(scope, name, session=session)
            all_metadata.update(metadata)
        return all_metadata
    else:
        for metadata_plugin in METADATA_PLUGIN_MODULES:
            if metadata_plugin.get_plugin_name().lower() == plugin.lower():
                return metadata_plugin.get_metadata(scope, name, session=session)  
    raise NotImplementedError('Metadata plugin "%s" is not enabled on the server.' % plugin)    #FIXME: this exception isn't returned correctly?


def set_metadata(scope, name, key, value, recursive=False, session=None):
    """
    Sets metadata for a given did.

    :param scope: The scope of the did.
    :param name: The data identifier name.
    :param key: Metadata key.
    :param value: Metadata value.
    :param recursive: (optional) Propagate the metadata change recursively to content.
    :param session: (optional) The database session in use.
    """
    # Sequentially check if each metadata plugin manages this key. Note that the order of [METADATA_PLUGIN_MODULES] 
    # means that the key is always checked for existence in the hardcoded list first.
    metadata_was_set = False
    for metadata_plugin in METADATA_PLUGIN_MODULES:
        if metadata_plugin.manages_key(key, session=session):
            metadata_plugin.set_metadata(scope, name, key, value, recursive, session=session)
            metadata_was_set = True
            break

    if not metadata_was_set:
        raise exception.InvalidMetadata('No plugin manages metadata key %s for DID %s:%s' % (key, scope, name))


def set_metadata_bulk(scope, name, metadata, recursive=False, session=None):
    """
    Bulk sets metadata for a given did.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param metadata: The key-value mapping of metadata to set.
    :param recursive: (optional) Propagate the metadata change recursively to content.
    :param session: (optional) The database session in use.
    """
    unmanaged_keys = list()
    if not isinstance(metadata, dict):
        metadata = dict(metadata)
    metadata_plugin_keys = {metadata_plugin: [] for metadata_plugin in METADATA_PLUGIN_MODULES}

    # Iterate through all keys, sequentially checking if each metadata plugin manages the considered key. If it 
    # does, add it to the list in the plugin's entry in {metadata_plugin_keys}. Note that the order of 
    # [METADATA_PLUGIN_MODULES] means that the key is always checked for existence in the hardcoded list first.
    for key in metadata.keys():
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


def delete_metadata(scope, name, key, session=None):
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
              offset=None, long=False, recursive=False, ignore_dids=None, session=None):
    """
    List dids according to metadata.

    Either all of the metadata in the query should belong in the hardcoded ones, or none at all.
    A mixture of hardcoded and generic metadata is not supported at the moment.

    :param scope: The scope of the did.
    :param filters: Dictionary of attributes by which the results should be filtered.
    :param did_type: The type of the did: all(container, dataset, file), collection(dataset or container), dataset, container, file.
    :param ignore_case: Ignore case distinctions.
    :param limit: Limit number.
    :param offset: Offset number.
    :param long: Long format option to display more information for each DID.
    :param recursive: Recursively list DIDs content.
    :param session: The database session in use.

    :returns: List of dids satisfying metadata criteria.
    """
    # Set [metadata_plugin_to_use] to be the first key's plugin... 
    metadata_plugin_to_use = None
    for or_group in filters:
        for key in or_group.keys():
            key_nooperator = key.split('.')[0]      # each key can have an operator attribute suffixed, i.e. <key>.<operator>
            if metadata_plugin_to_use is None:
                for metadata_plugin in METADATA_PLUGIN_MODULES:
                    if metadata_plugin.manages_key(key_nooperator, session=session):
                        metadata_plugin_to_use = metadata_plugin
                        break
            else:   # ... then check that this plugin manages the rest of the keys.
                if not metadata_plugin_to_use.manages_key(key_nooperator, session=session):
                    raise NotImplementedError('Filter keys used do not all belong to the same metadata plugin.')    #FIXME: this exception isn't returned correctly?
    if metadata_plugin_to_use:
        return metadata_plugin_to_use.list_dids(scope=scope, filters=filters, did_type=did_type,
                                                ignore_case=ignore_case, limit=limit,
                                                offset=offset, long=long, recursive=recursive, 
                                                ignore_dids=ignore_dids, session=session)
    else:
        raise NotImplementedError('There is no metadata plugin that manages the filter keys you requested.')        #FIXME: this exception isn't returned correctly?
