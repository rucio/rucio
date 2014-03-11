#!/bin/bash
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014

while read -r l
do
    echo $l
done < <(
    for i in $(shuf -e $SITES)
    do
        for j in $(shuf -e $SITES)
        do
            echo bin/mock/rucio-conveyor-injector --run-once --src $i --dst $j
        done
    done | perl -ne 'print if (rand() < .001)')
