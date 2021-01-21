DID Metadata
===========

Rucio supports adding Metadata on the dids.

Example::
    # Create a dataset to use on the Example
    $ rucio add-dataset mock:testing_metadata

    # Add 'optimized' metadata that exist as columns in the did table
    $ rucio set-metadata --did mock:testing_metadata --key panda_id --value 9999

    # Add 'generic' metadata. If there is no custom metadata plugin, the plugin 'JSON' will be used
    $ rucio set-metadata --did mock:testing_metadata --key random_key_name --value 8888
    
    # Get the 'optimized' metadata
    $ rucio get-metadata mock:testing_metadata

    # Get the Generic metadata
    $ rucio get-metadata mock:testing_metadata --plugin JSON

    # Get all the metadata
    $ rucio get-metadata mock:testing_metadata --plugin ALL

    # List dids according to metadata
    $ rucio list-dids-extended mock:* --filter "type=ALL,panda_id=9999"
    $ rucio list-dids-extended mock:* --filter "type=ALL,random_key_name=8888"


Even though regular users use metadata out of the box using the CLI, advanced users and Rucio admins should be aware that in the backend there are multiple options on how to store and manage the did metadata per experiment needs.

The concepts of DID Metadata Plugins exists on Rucio. While deploying the Rucio server you can configure which existing did plugins to use or even develop your own.

The default plugin in use the one originally developed for the needs of ATLAS, stores the metadata on fixed columns on the DID table and is the most optimal for the specific metadata.

Another option available is the JSON metadata plugin which stores the metadata in JSON blobs in the relational databased used by the Rucio Server.

When you are trying to add or fetch a VALUE for a given KEY, Rucio which asks in order each configured metadata plugin if it supports this KEY.

How to develop a custom metadata solution
-------------------

The module you develop needs to extend the [DidMetaPlugin](/) Abstract class. The methods needed are ::

    get_metadata(scope, name, session=None)
    """
    Returns metadata stored in Plugin for given scope:name
    """

    set_metadata(scope, name, key, value, recursive, session=None)
    """
    Sets the metadata in Plugin for given scope:name
    """

    delete_metadata(scope, name, key, session=None)
    """
    Removes the metadata from the Plugin for given scope:name
    """

    list_dids(scope, filters, type='collection', ignore_case=False, limit=None, offset=None, long=False, recursive=False, session=None)
    """
    Returns a list of dids for given filters.
    For long = True return should be a list of dictionaries having the keys 'scope', 'name', 'did_type', 'bytes', 'length'.
    For long = False return should be a list of strings containing the did names.
    """

    manages_key(key, session=None)
    """
    Returns if Plugin is willing to manage metadata with given KEY.
    Some Plugins might decide to accept only specific hardcoded keys, others might match against a particular regex while other might accept all possible keys.
    """

How to configure which metadata plugin to use
-------------------
Configuration options for Metadata are::

    [metadata]
    # plugins = [list_of_plugins,comma_separated]
    plugins = [rucio.core.did_meta_plugins.did_column_meta.DidColumnMeta, escape.rucio.did_meta_plugin]
