..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

-----------------------
Authenticate with rucio
-----------------------

.. sequence-diagram::
   :maxwidth: 600
   :linewrap: false
   :threadnumber: true

   client:Client
   rucio:Server(Auth)

   client:rucio.GET auth/{userpass|x509|gss}
   client:rucio.GET/PUT/DELETE/POST -H token ...