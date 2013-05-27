..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

------------------------------------------------
Search datasets with wildcard pattern, meta-data
------------------------------------------------

* Search via pattern

.. sequence-diagram::

    HTTPClient::
    REST::
    Core::
    DB::

    HTTPClient:[datasets]=REST.GET /datasets/{regular expression}
    REST:[datasets]=Core.searchDatasets({regular expression})
    Core:[datasets]=DB.retrieve({regular expression})

* Search via meta-data

.. sequence-diagram::

    HTTPClient::
    REST::
    Core::
    DB::

    HTTPClient:[datasets]=REST.POST /datasets/search
    REST:[datasets]=Core.searchDatasets({dictionary})
    Core:[datasets]=DB.retrieve({dictionary})

Body of the POST is a JSON dictionary with the appropriate key/value pairs, e.g. ``{'project':'data11*', 'datatype':'raw'}``.
