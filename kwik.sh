#!/bin/sh
if [ ! -f libs/flupke-plugin.jar ]; then
  echo "No flupke plugin found in libs directory; http requests will use HTTP 0.9!"
fi
kwikjar=`ls build/libs/kwik* | grep -v javadoc | grep -v sources 2> /dev/null`
if [ ! -f "$kwikjar" ]; then
    echo "Cannot find kwik jar file"
    exit
fi
java -Duser.language=en -Duser.country=US -cp $kwikjar:libs/flupke-plugin.jar net.luminis.quic.run.KwikCli $*
