#!/bin/bash

javac -cp `hadoop classpath`:WEB-INF/lib/*:. ruciotools/HttpMonitoring.java && rm -rf WEB-INF/classes/ruciotools && cp -rf ruciotools WEB-INF/classes/. && jar cf HttpMonitoring.war * && mv HttpMonitoring.war /usr/share/tomcat/webapps/HttpMonitoring.war

