----------------------
Upload file into rucio
----------------------

.. _usecase_upload_file_into_rucio:

::

    rucio-client -> rucio-server CALL    auth(**)
    rucio-client <- rucio-server RETURNS token

    rucio-client -> rucio-server CALL    registerFileToLocation(**)
    rucio-client <- rucio-server RETURNS ok

    rucio-client -> storage      CALL    uploadFile(**)

    rucio-client -> rucio-server CALL    commitRegistration(**)
    rucio-client <- rucio-server RETURNS ok
