#!/bin/bash

shopt -s nullglob
distro=(cli/build/distributions/kwik-cli-*.zip)
if [ ${#distro[@]} -lt 1 ]; then
    echo "Error: no Kwik distro's found, execute 'gradle build' to get one."
    exit
fi
if [ ${#distro[@]} -ne 1 ]; then
    distro=`ls -t1 ${distro[@]} | head -1`
    echo "Warning: multiple Kwik distro's found, using newest: $distro"
    echo "if you agree...."
    echo "so: using $distro"
fi

shopt -u nullglob
if [ -f $distro ]; then
    if [ -d dist/kwik-cli-*/lib ]; then
	if [ $distro -nt dist/kwik-cli-*/lib ]; then
	    rm -rf dist/kwik-cli-*
	fi
    fi
    if [ ! -d dist/kwik-cli-*/lib ]; then
	mkdir -p dist
	unzip -q -d dist $distro
	touch dist/kwik-cli-*/lib
	if [ ! -f libs/flupke.jar ]; then
	    echo "No flupke jar found in libs directory; http requests will use HTTP 0.9!"
	    echo
	elif [ ! -f libs/qpack-2.0.1.jar ]; then
	    echo "No qpack-2.0.1 jar found in libs directory; http requests will use HTTP 0.9!"
	    echo
	else
	    sed -i '' 's@CLASSPATH=$APP_HOME@CLASSPATH=libs/flupke.jar:libs/qpack-2.0.1.jar:$APP_HOME@' dist/kwik-cli-*/bin/kwik-cli
	fi
    fi
    echo 
    dist/kwik-cli-*/bin/kwik-cli $*
    exit
fi
