..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

==================
Rucio CLI Examples
==================


``rucio --version``
-------------------
Print version information::

   $> rucio --version
   
``rucio ping``
--------------
Discover server version information::

   $> rucio ping
   0-42-gd374efe-dev1350397766

``rucio add-replicas``
----------------------
Add file replicas::

   $> rucio add-replicas  --lfns vgaronne:Myfile vgaronne:Myfile1 vgaronne:Myfile2 --rses MOCK1 MOCK1 MOCK1 --checksums ad:92ce22ac ad:92ce22ab ad:92ce22ac  --sizes 2849063278 2849063277 2849063279 --dsn vgaronne:MyDataset
   Added file replica vgaronne:Myfile at MOCK1
   Added file replica vgaronne:Myfile1 at MOCK1
   Added file replica vgaronne:Myfile2 at MOCK1
   
``rucio add``
-------------
Add dataset/container and content::

   $> rucio add --dest vgaronne:MyDataset1 --srcs vgaronne:Myfile vgaronne:Myfile1
   Added: vgaronne:MyDataset1
   
   $> rucio add --dest vgaronne:MyDataset2 --srcs vgaronne:Myfile2
   Added: vgaronne:MyDataset2
   
   $> rucio add --dest vgaronne:MyContainer1 --srcs vgaronne:MyDataset1 vgaronne:MyDataset2
   Added: vgaronne:MyContainer1
   
   $> rucio add --dest vgaronne:MyBigContainer1 --srcs vgaronne:MyContainer1
   Added: vgaronne:MyBigContainer1
   
``rucio del``
--------------
delete container/dataset or contents::

   $> rucio del vgaronne:MyDataset1 --from vgaronne:MyContainer1
   
``rucio list``
--------------
List container/dataset contents::

   $> rucio list vgaronne:MyDataset
   vgaronne:Myfile
   vgaronne:Myfile1
   vgaronne:Myfile2
   
   $> rucio list vgaronne:MyBigContainer1
   vgaronne:MyContainer1
   
   $> rucio list vgaronne:MyContainer1
   vgaronne:MyDataset1
   vgaronne:MyDataset2
   
   $> rucio list vgaronne:MyDataset1
   vgaronne:Myfile
   vgaronne:Myfile1
   
``rucio list-files``
-----------------------
List file contents::

   $> rucio list-files vgaronne:MyDataset1
   vgaronne:Myfile
   vgaronne:Myfile1
   
   $> rucio list-files vgaronne:MyBigContainer1
   vgaronne:Myfile2
   vgaronne:Myfile
   vgaronne:Myfile1
   
``rucio list-replicas``
-----------------------
List file replicas::

   $> rucio list-replicas vgaronne:Myfile1
   vgaronne:Myfile1: MOCK1
   
   $> rucio list-replicas vgaronne:MyDataset
   vgaronne:Myfile2: MOCK1
   vgaronne:Myfile: MOCK1
   vgaronne:Myfile1: MOCK1
   
   $> rucio list-replicas vgaronne:MyBigContainer1
   vgaronne:Myfile2: MOCK1
   vgaronne:Myfile: MOCK1
   vgaronne:Myfile1: MOCK1
   
``rucio upload``
----------------
Upload data into rucio::

   $> rucio upload --rse MOCK --scope vgaronne --files Myfile4 --dsn Mydataset4
   Loading credentials from /Users/garonne/Lab/rucio/etc/rse-accounts.cfg
   Loading repository data from /Users/garonne/Lab/rucio/etc/rse_repository.json
   Upload**Upload**Upload**Upload**Upload**Upload**Upload**Upload**Upload**Upload**
   Sourcefile: ./Myfile4
   Target: vgaronne:Myfile4 
   Trans: /tmp/rucio_rse/vgaronne/a3/44/39/Myfile4
   Upload**Upload**Upload**Upload**Upload**Upload**Upload**Upload**Upload**Upload**
   download operation for Myfile4 done
   
``rucio download``
------------------
download data from rucio::

   $> rucio download --dir=/tmp/download  vgaronne:Myfile4
   Loading credentials from /Users/garonne/Lab/rucio/etc/rse-accounts.cfg
   Loading repository data from /Users/garonne/Lab/rucio/etc/rse_repository.json
   Download**Download**Download**Download**Download**Download**Download**Download**Download**Download**
   Sourcefile: /tmp/rucio_rse/vgaronne/a3/44/39/Myfile4
   Target: /tmp/download/vgaronne/Myfile4 
   Download**Download**Download**Download**Download**Download**Download**Download**Download**Download**
   download operation for vgaronne:Myfile4 done
   
   $> ls /tmp/download/vgaronne/
   Myfile4
   
``rucio search``
----------------
Search data identifiers::

To Do

``rucio get-metadata``
----------------------
To Do

``rucio set-metadata``
----------------------
To Do

``rucio del-metadata``
----------------------
To Do

``rucio list-rse-usage``
------------------------
To Do::

   $> rucio list-rse-usage MOCK
   
   $> rucio list-rse-usage --history MOCK
   
``rucio list-account-usage``
----------------------------
To Do::

   $> rucio list-account-usage --history
   
   $> rucio list-account-limits
   
