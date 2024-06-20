#!/bin/sh

if [ -f cli/build/distributions/kwik-cli-v*.zip ]; then
    if [ -d dist/kwik-cli-v*/lib ]; then
	if [ cli/build/distributions/kwik-cli-v*.zip -nt dist/kwik-cli-v*/lib ]; then
	    rm -rf dist/kwik-cli-v*
	fi
    fi
    if [ ! -d dist/kwik-cli-v*/lib ]; then
	mkdir -p dist
	unzip -d dist cli/build/distributions/kwik-cli-v*.zip
	touch dist/kwik-cli-v*/lib
	if [ ! -f libs/flupke.jar ]; then
	    echo "No flupke jar found in libs directory; http requests will use HTTP 0.9!"
	    echo
	else
	    sed -i '' 's@CLASSPATH=$APP_HOME@CLASSPATH=libs/flupke.jar:$APP_HOME@' dist/kwik-cli-v*/bin/kwik-cli
	fi
    fi
    dist/kwik-cli-v*/bin/kwik-cli $*
    exit
fi
