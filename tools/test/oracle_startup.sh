#!/bin/sh

export ORACLE_HOME=/u01/app/oracle/product/11.2.0/xe
export PATH=$ORACLE_HOME/bin:$PATH
export ORACLE_SID=XE

LISTENER_ORA=/u01/app/oracle/product/11.2.0/xe/network/admin/listener.ora
TNSNAMES_ORA=/u01/app/oracle/product/11.2.0/xe/network/admin/tnsnames.ora

su oracle -s /bin/bash -c "$ORACLE_HOME/bin/sqlplus -s SYSTEM/oracle as sysdba" << EOF
whenever oserror exit oscode;
whenever sqlerror exit sql.sqlcode;
startup
EOF
