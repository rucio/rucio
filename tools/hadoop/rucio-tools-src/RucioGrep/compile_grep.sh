#!/bin/bash

javac -cp `hadoop classpath` ruciotools/Grep.java && jar cf MRGrep.jar ruciotools/Grep*.class
