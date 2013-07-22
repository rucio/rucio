.. http:post:: /dids/attachments

   Add data identifiers to data identifiers.

   **Example request**:

   .. sourcecode:: http

      POST /dids/attachments HTTP/1.1
      Host: example.com
      Accept: application/json

   **Example response**:

   .. sourcecode:: http

      HTTP/1.1 201 Created
      Vary: Accept

   :statuscode 201: Created
