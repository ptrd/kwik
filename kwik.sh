#!/bin/sh
if [ ! -f libs/flupke-plugin.jar ]; then
  echo "No flupke plugin found in libs directory; http requests will use HTTP 0.9!"
fi
java -Duser.language=en -Duser.country=US -cp build/libs/kwik.jar:libs/flupke-plugin.jar net.luminis.quic.run.KwikCli $*
