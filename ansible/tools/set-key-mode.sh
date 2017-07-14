#!/bin/bash

# SSH requires that keys have a mode 0600 for security. It will not use keys
# that have more permissive permissions than this. Git only tracks the
# executable bit, so this script will fix everything.

# ./set-key-mode.sh /path/to/keyfile
# Example
# ./set-key-mode.sh ./keys/stg/stg

set -e

if [ -z "$1" ]; then
    echo "Please specify the keys file"
    exit 1
fi

if [ -f "$1" ]
then
	echo "$1 found."
	chmod --changes 0600 $1
	echo "$1 Permissions Updated"
else
	echo "$1 not found. Exiting..."
	exit 1
fi

exit 0
