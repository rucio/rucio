--------------
Exception and error handling
--------------

***************************
Exception Handling in Rucio
***************************

In Rucio, state is kept at the database level. Consequently many exceptions originate from the ORM layer. These exceptions will be caught at the CORE layer, and translated into meaningful Rucio exceptions.

In the case where REST processes catch a Rucio exception, they will communicate to the client the HTTP error code, the name of the exception, and the corresponding error string. The reason for sending the name of the exception is that HTTP error codes can map to multiple exceptions, and consequently client code cannot use the HTTP error code to ascertain the type of exception that occured.

An application directly quering the REST interface will receive the exception details as a string. The Rucio client API will raise an exception based on the information parsed from the HTTP response.

This process is summarised in the following diagram.

.. image:: images/exception_handling.png
    :scale: 80 %
    :alt: Figure 1
    :align: center
