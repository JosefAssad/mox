#!/usr/bin/env bash

while getopts ":das" OPT; do
  case $OPT in
  	d)
			DB_INSTALL=1
			;;
		s)
			SKIP_SYSTEM_DEPS=1
			;;
		*)
			echo "Usage: $0 [-d] [-a] [-s]"
			echo "	-d: Install and (re-)create the DB"
			echo "	-a: Install the MOX agents"
			echo "	-s: Skip installing oio_rest API system dependencies"
			exit 1;
			;;
	esac
done

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )


# Add system user if none exists
getent passwd mox
if [ $? -ne 0 ]; then 
	echo "Creating system user 'mox'"
	sudo useradd mox
fi



# INSTALL OIO_REST


## System dependencies. These are the packages we need that are not present on a
## fresh OS install.
## Virtualenv is usually among these
#
if [ -z $SKIP_SYSTEM_DEPS ]; then
    echo "Installing oio_rest dependencies"
	SYSTEM_PACKAGES=$(cat "$DIR/oio_rest/SYSTEM_DEPENDENCIES")

	for package in "${SYSTEM_PACKAGES[@]}"; do
		sudo apt-get -y install $package
	done
fi

# Create the MOX content storage directory and give the mox user ownership
MOX_STORAGE="/var/mox"
echo "Creating MOX content storage directory"
sudo mkdir -p "$MOX_STORAGE"
sudo chown mox "$MOX_STORAGE"

# Setup and start virtual environment
echo "Setting up virtual enviroment"
VIRTUALENV=$DIR/oio_rest/python-env

if [ -d $VIRTUALENV ]; then
	rm -rf $VIRTUALENV
fi

virtualenv $VIRTUALENV

if [ ! -d $VIRTUALENV ]; then
	echo "Virtual environment not created!"
else
	echo "Starting virtual environment"
	source $VIRTUALENV/bin/activate

	pushd $DIR/oio_rest
	python setup.py develop
	popd

	if [ ! -z $DB_INSTALL ]; then

		SYSTEM_PACKAGES=$(cat "$DIR/db/SYSTEM_DEPENDENCIES")
		for package in "${SYSTEM_PACKAGES[@]}"; do
			sudo apt-get -y install $package
		done

		echo "Installing DB"

		cd $DIR/db
		./install.sh
		cd $DIR/db
		./recreatedb.sh
		cd $DIR
	fi
	deactivate

	echo "Run oio_rest/oio_api.sh to test API"

fi

# Create log dir
echo "Creating log dir"
sudo mkdir -p "/var/log/mox"


# Set up oio_rest apache service
$DIR/oio_rest/install.sh

echo "Installing java modules"
sudo apt-get -y install maven

$DIR/modules/agent/install.sh
$DIR/modules/auth/install.sh
$DIR/modules/json/install.sh
$DIR/modules/spreadsheet/install.sh

