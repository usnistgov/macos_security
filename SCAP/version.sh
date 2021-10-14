#!/bin/bash

VERSION=$(/usr/bin/awk -F ": " '/version/{print $2}' ../VERSION.yaml | /usr/bin/awk '{print $NF}' | /usr/bin/tr -d '"')
echo $VERSION