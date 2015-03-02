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
        date=`date '+%Y-%m-%d'`
else
        date=$1
fi

NUM=( 01 02 03 04 07 08 09 10 11 )
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

for number in "${NUM[@]}"; do
	echo "[`date`] Start parsing log file from rucio-server-prod-$number from $date"
	KRB5CCNAME=/tmp/rucio01.tgt hadoop fs -cat logs/server/access*server-prod-*$number*$date* | python $DIR/RucioServerLogs2Graphite.py
	echo "[`date`] Finished parsing log file from rucio-server-prod-$number from $date"
done
