#!/bin/bash

javac -cp /usr/lib/pig/piggybank.jar:/usr/lib/pig/pig.jar:. rucioloader/*.java && jar cf rucioloader.jar rucioloader/*
