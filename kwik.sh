#!/bin/sh

askForConfirmation() {
    while true; do
        read -p "Ok to continue? [y/n]: " yn
        case $yn in
            [Yy]* ) break;;
            [Nn]* ) echo "Aborting"; exit;;
            * ) echo "Please answer yes or no.";;
        esac
    done
}
checkOrDownloadDependency() {
  if [ ! -f libs/$1 ]; then
    echo "Downloading missing dependency $1 to 'libs/' directory"
    askForConfirmation
    curl -L -o libs/$1 $2
    unzip -t libs/$1 > /dev/null 2>&1
    if [ $? -ne 0 ]; then
      echo "Failed to download $1 from $2"
      exit 1
    fi
    echo
  fi
}

mkdir -p libs
checkOrDownloadDependency agent15-1.1.jar https://repo1.maven.org/maven2/tech/kwik/agent15/1.1/agent15-1.1.jar
checkOrDownloadDependency hkdf-2.0.0.jar https://repo1.maven.org/maven2/at/favre/lib/hkdf/2.0.0/hkdf-2.0.0.jar
checkOrDownloadDependency commons-cli-1.4.jar https://repo1.maven.org/maven2/commons-cli/commons-cli/1.4/commons-cli-1.4.jar

if [ ! -f libs/flupke.jar ]; then
  echo "No flupke jar found in libs directory; http requests will use HTTP 0.9!"
  echo
fi
kwikcorejar=`ls core/build/libs/kwik*.jar | grep -v javadoc | grep -v sources 2> /dev/null`
if [ ! -f "$kwikcorejar" ]; then
    echo "Cannot find kwik jar file"
    exit
fi
kwikclijar=`ls cli/build/libs/kwik*.jar | grep -v javadoc | grep -v sources 2> /dev/null`
if [ ! -f "$kwikclijar" ]; then
    echo "Cannot find kwik cli jar file"
    exit
fi
kwikh09jar=`ls h09/build/libs/kwik*.jar | grep -v javadoc | grep -v sources 2> /dev/null`
if [ ! -f "$kwikh09jar" ]; then
    echo "Cannot find kwik H09 jar file"
    exit
fi

CLASSPATH=$kwikcorejar:$kwikclijar:$kwikh09jar:libs/agent15-1.1.jar:libs/hkdf-2.0.0.jar:libs/commons-cli-1.4.jar:libs/flupke.jar
java -Duser.language=en -Duser.country=US -cp $CLASSPATH net.luminis.quic.cli.KwikCli $*
