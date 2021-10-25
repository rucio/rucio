#!/bin/sh

export ORACLE_HOME=/opt/oracle/product/18c/dbhomeXE/
export PATH=$ORACLE_HOME/bin:$PATH
export ORACLE_SID=XE

LISTENER_ORA=/opt/oracle/product/18c/dbhomeXE/network/admin/listener.ora
TNSNAMES_ORA=/opt/oracle/product/18c/dbhomeXE/network/admin/tnsnames.ora

echo alter system set processes = $processes scope = spfile\; | oracle -s /bin/bash -c "$ORACLE_HOME/bin/sqlplus -s SYSTEM/oracle as sysdba"
echo alter system set sessions = $sessions scope = spfile\; | oracle -s /bin/bash -c "$ORACLE_HOME/bin/sqlplus -s SYSTEM/oracle as sysdba"
echo alter system set transactions = $transactions scope = spfile\; | oracle -s /bin/bash -c "$ORACLE_HOME/bin/sqlplus -s SYSTEM/oracle as sysdba"
echo shutdown immediate\; | oracle -s /bin/bash -c "$ORACLE_HOME/bin/sqlplus -s SYSTEM/oracle as sysdba"
echo startup\; | oracle -s /bin/bash -c "$ORACLE_HOME/bin/sqlplus -s SYSTEM/oracle as sysdba"

#echo "\nproddcesses=1000" >> /u01/app/oracle/product/11.2.0/xe/config/scripts/init.ora
#echo "\nprocesses=1000" >> /u01/app/oracle/product/11.2.0/xe/config/scripts/initXETemp.ora
#sed -i -E "s/sessions=[^)]+/sessions=1105/g" /u01/app/oracle/product/11.2.0/xe/config/scripts/init.ora
#sed -i -E "s/sessions=[^)]+/sessions=1105/g" /u01/app/oracle/product/11.2.0/xe/config/scripts/initXETemp.ora
#echo "\ntransactions=1215" >> /u01/app/oracle/product/11.2.0/xe/config/scripts/init.ora
#echo "\ntransactions=1215" >> /u01/app/oracle/product/11.2.0/xe/config/scripts/initXETemp.ora
