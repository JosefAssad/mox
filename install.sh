#!/usr/bin/env bash

# TODO: bail if root
if [ `id -u` == 0 ]; then
	echo "Do not run as root. We'll sudo when necessary"
	exit 1;
fi

while getopts ":ys" OPT; do
  case $OPT in
	s)
		SKIP_SYSTEM_DEPS=1
		;;
	y)
		ALWAYS_CONFIRM=1
		;;
	*)
		echo "Usage: $0 [-y] [-s]"
		echo "	-s: Skip installing oio_rest API system dependencies"
		echo "	-y: Always confirm (yes) when prompted"
		exit 1;
		;;
	esac
done

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

# Query for hostname
DOMAIN=`hostname --fqdn`
read -p "Domain: [$DOMAIN] " -r
echo
if [[ "x$REPLY" != "x" ]]; then
	DOMAIN="$REPLY"
fi

# Add system user if none exists
getent passwd mox
if [ $? -ne 0 ]; then 
	echo "Creating system user 'mox'"
	sudo useradd mox
fi

# Create log dir
echo "Creating log dir"
sudo mkdir --parents "/var/log/mox"

# Setup common config
MOX_CONFIG="$DIR/mox.conf"
sudo cp --remove-destination "$MOX_CONFIG.base" "$MOX_CONFIG"

MOX_OIO_CONFIG="$DIR/oio_rest/oio_rest/settings.py"
sudo cp --remove-destination "$MOX_OIO_CONFIG.base" "$MOX_OIO_CONFIG"

MOX_APACHE_CONFIG="$DIR/apache/mox.conf"
sudo cp --remove-destination "$MOX_APACHE_CONFIG.base" "$MOX_APACHE_CONFIG"

MOX_AUTH_CONFIG="$DIR/modules/auth/auth.properties"
sudo cp --remove-destination "$MOX_AUTH_CONFIG.base" "$MOX_AUTH_CONFIG"



sed --in-place --expression="s|\${domain}|${DOMAIN}|" "$MOX_CONFIG"

VARIABLESFILENAME="$DIR/variables.sh"
cp --remove-destination "$VARIABLESFILENAME.base" "$VARIABLESFILENAME"

# Setup apache virtualhost
echo "Setting up Apache virtualhost"
$DIR/apache/install.sh -d $DOMAIN

echo "Setting up Identity Server"
$DIR/wso2/install.sh "$DOMAIN"

# Install oio_rest
echo "Installing oio_rest"
echo "$DIR/oio_rest/install.sh $@"
$DIR/oio_rest/install.sh "$@" -d $DOMAIN


JAVA_HIGHEST_VERSION=0
JAVA_VERSION_NEEDED=8
JAVA_HIGHEST_VERSION_DIR=""
SHELL_VARIABLES_FILE="$DIR/variables.sh"
regex=".*/java-([0-9]+).*"
files=`find /usr/lib -wholename '*/bin/javac' -perm -a=x -type f`
for f in $files; do
	if [[ $f =~ $regex ]]; then
		version="${BASH_REMATCH[1]}"
		if [[ $version > $JAVA_HIGHEST_VERSION ]]; then
			JAVA_HIGHEST_VERSION=$version
			JAVA_HIGHEST_VERSION_DIR=$(readlink -m "$f/../..")
		fi
    fi
done
if [ $JAVA_HIGHEST_VERSION -ge $JAVA_VERSION_NEEDED ]; then
	echo "Java is installed in version $JAVA_HIGHEST_VERSION"
else
	echo "Installing java in version $JAVA_VERSION_NEEDED"
	sudo apt-cache -q=2 show "openjdk-$JAVA_VERSION_NEEDED-jdk" 2> /dev/null 1> /dev/null
	if [[ $? > 0 ]]; then
		# openjdk is not available in the version we want
		sudo add-apt-repository ppa:openjdk-r/ppa
		sudo apt-get update > /dev/null
	fi
	sudo apt-get --yes --quiet install "openjdk-$JAVA_VERSION_NEEDED-jdk"
fi
if [[ "x$JAVA_HIGHEST_VERSION_DIR" != "x" ]]; then
	sed -r -e "s|^CMD_JAVA=.*$|CMD_JAVA=$JAVA_HIGHEST_VERSION_DIR/bin/java|" \
       -e "s|^CMD_JAVAC=.*$|CMD_JAVAC=$JAVA_HIGHEST_VERSION_DIR/bin/javac|" \
       ${SHELL_VARIABLES_FILE} > ${SHELL_VARIABLES_FILE}.$$
fi
if [[ -f ${SHELL_VARIABLES_FILE}.$$ ]]; then
	/bin/mv ${SHELL_VARIABLES_FILE}.$$ ${SHELL_VARIABLES_FILE}
fi

OLD_JAVA_HOME="$JAVA_HOME"
JAVA_HOME="$JAVA_HIGHEST_VERSION_DIR"

# Install Maven
echo "Installing Maven"
sudo apt-get --yes --quiet install maven

# Compile modules
echo "Installing java modules"
$DIR/modules/json/install.sh
$DIR/modules/agent/install.sh
$DIR/modules/auth/install.sh

# Install servlet
echo "Installing Tomcat webservices"
$DIR/servlets/install.sh
$DIR/servlets/MoxDocumentUpload/install.sh "$DOMAIN"

$DIR/scripts/install.sh

# Compile agents
echo "Installing Agents"
$DIR/agents/MoxTabel/install.sh
$DIR/agents/MoxRestFrontend/install.sh
$DIR/agents/MoxTest/install.sh

JAVA_HOME="$OLD_JAVA_HOME"

sudo chown --recursive mox:mox $DIR
sudo service apache2 reload

