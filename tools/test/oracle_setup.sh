#!/bin/sh

export ORACLE_HOME=/u01/app/oracle/product/11.2.0/xe
export PATH=$ORACLE_HOME/bin:$PATH
export ORACLE_SID=XE

LISTENER_ORA=/u01/app/oracle/product/11.2.0/xe/network/admin/listener.ora
TNSNAMES_ORA=/u01/app/oracle/product/11.2.0/xe/network/admin/tnsnames.ora

echo alter system set processes = 1000 scope = spfile\; | su oracle -s /bin/bash -c "$ORACLE_HOME/bin/sqlplus -s SYSTEM/oracle as sysdba"
echo alter system set sessions = 1105 scope = spfile\; | su oracle -s /bin/bash -c "$ORACLE_HOME/bin/sqlplus -s SYSTEM/oracle as sysdba" 
echo alter system set transactions = 1215 scope = spfile\; | su oracle -s /bin/bash -c "$ORACLE_HOME/bin/sqlplus -s SYSTEM/oracle as sysdba"
echo shutdown immediate\; | su oracle -s /bin/bash -c "$ORACLE_HOME/bin/sqlplus -s SYSTEM/oracle as sysdba"
echo startup\; | su oracle -s /bin/bash -c "$ORACLE_HOME/bin/sqlplus -s SYSTEM/oracle as sysdba"

#echo "\nproddcesses=1000" >> /u01/app/oracle/product/11.2.0/xe/config/scripts/init.ora
#echo "\nprocesses=1000" >> /u01/app/oracle/product/11.2.0/xe/config/scripts/initXETemp.ora
#sed -i -E "s/sessions=[^)]+/sessions=1105/g" /u01/app/oracle/product/11.2.0/xe/config/scripts/init.ora
#sed -i -E "s/sessions=[^)]+/sessions=1105/g" /u01/app/oracle/product/11.2.0/xe/config/scripts/initXETemp.ora
#echo "\ntransactions=1215" >> /u01/app/oracle/product/11.2.0/xe/config/scripts/init.ora
#echo "\ntransactions=1215" >> /u01/app/oracle/product/11.2.0/xe/config/scripts/initXETemp.ora
