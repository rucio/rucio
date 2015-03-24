#!/bin/bash

# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne <ralph.vigne@cern.ch>, 2015
#


script_name=$1
date=$2
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

echo "[`date`] INFO: Check for temp folder and delete if present"
KRB5CCNAME=/tmp/rucio01.tgt hadoop fs -rm -r tmp/requests_daily/${script_name}.csv 

echo "[`date`] INFO: Running ${script_name}.pig for $date"
KRB5CCNAME=/tmp/rucio01.tgt pig -f ${DIR}/${script_name}.pig -param date=$date

KRB5CCNAME=/tmp/rucio01.tgt hadoop fs -stat tmp/requests_daily/${script_name}.csv/_SUCCESS
if [[ $? != 0 ]]; then
	echo "[`date`] ERROR: PIG Script '${script_name}' failed"
	exit 1
else
	echo "[`date`] INFO: PIG Script '${script_name}' executed successfully"
fi


echo "[`date`] INFO: Copy to local disk"
KRB5CCNAME=/tmp/rucio01.tgt hadoop fs -copyToLocal tmp/requests_daily/${script_name}.csv/part-r-00000 ${DIR}/tmp_http_report_${script_name}.csv
if [[ $? != 0 ]]; then
	echo "[`date`] ERROR: Failed copying report to local disk"
	exit 1
fi

if [[ $script_name == 'per_country' ]]; then
	echo "[`date`] INFO: Resolving client ip to country ISO code"
	python ${DIR}/subs_ip_by_country.py ${DIR}/tmp_http_report_${script_name}.csv ${DIR}/tmp_http_report_${script_name}.substituted.csv
	mv ${DIR}/tmp_http_report_${script_name}.substituted.csv ${DIR}/tmp_http_report_${script_name}.csv
fi

echo "[`date`] INFO: Prepend schema (column names)"
cat ${DIR}/${script_name}.schema ${DIR}/tmp_http_report_${script_name}.csv > ${DIR}/tmp_http_report_${script_name}_w_header.csv
if [[ $? != 0 ]]; then
	echo "[`date`] ERROR: Failed copying report to local disk"
	exit 1
fi

echo "[`date`] INFO: Creating target directory, in case it didn;t exist already"
KRB5CCNAME=/tmp/rucio01.tgt hadoop fs -mkdir reports/$date


echo "[`date`] INFO: Removing outdated file eports/$date/http_monitoring_${script_name}.csv"
KRB5CCNAME=/tmp/rucio01.tgt hadoop fs -rm reports/$date/http_monitoring_${script_name}.csv

echo "[`date`] INFO: Copy report file back to HDFS"
KRB5CCNAME=/tmp/rucio01.tgt hadoop fs -copyFromLocal ${DIR}/tmp_http_report_${script_name}_w_header.csv reports/$date/http_monitoring_${script_name}.csv
if [[ $? != 0 ]]; then
	echo "[`date`] ERROR: Failed copying report back to HDFS"
	exit 1
fi

echo "[`date`] INFO: Removing temp folder"
KRB5CCNAME=/tmp/rucio01.tgt hadoop fs -rm -r tmp/requests_daily/${script_name}.csv

echo "[`date`] INFO: Removing local temp files"
rm ${DIR}/tmp_http_report_${script_name}*.csv -f

echo "[`date`] INFO: Script \"${DIR}/${script_name}\" - it's `date +%H:%M` o'clock, and all's well!"
exit 0
