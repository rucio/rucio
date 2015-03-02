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



if [ $# -eq 0 ]; then
	date=`date --date='yesterday' '+%Y-%m-%d'`
else
	date=$1
fi

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

for script_file in ${DIR}/*.pig; do
	script_name=(`basename ${script_file} | cut -d '.' -f 1`)
	${DIR}/create_report.sh $script_name $date
done

${DIR}/run_log2graphite.sh $date
