#!/bin/sh

CONNECTION_DID=$2
CONFIG_FILE=$4
LOG=$6

MESSAGE=$CONNECTION_DID" "$CONFIG_FILE" "$LOG

echo $MESSAGE > tmp.txt
echo $MESSAGE