#!/bin/bash

OS=$(/usr/bin/awk -F ": " '/os/{print $2}' ../VERSION.yaml | /usr/bin/tr -d '"')

echo $OS