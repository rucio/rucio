#!/bin/bash

javac -cp `hadoop classpath`:/usr/lib/pig/piggybank.jar:/usr/lib/pig/pig.jar:. rucioudfs/*.java && jar cf rucioudfs.jar rucioudfs/*
