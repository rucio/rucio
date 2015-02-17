#!/bin/bash


javac -cp `hadoop classpath` ruciotools/*.java && rm -rf WEB-INF/classes/* && cp -r ruciotools WEB-INF/classes/. && jar cf /usr/share/tomcat/webapps/WebMRGrep.war *
