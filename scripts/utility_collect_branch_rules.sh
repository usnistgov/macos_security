#!/bin/bash

# verify that no unstage changes exist

GIT_STATUS=$(git status --porcelain=v1 2>/dev/null | wc -l | xargs)

if [[ ! $GIT_STATUS == 0 ]]; then
    echo "There are unstaged changes here, please resolve before continuing."
    exit 1
fi

# branches to check out

branches=("sequoia" "sonoma" "ventura" "monterey" "catalina" "big_sur" "ios_16" "ios_17" "ios_18" "visionos")

# get all of the branches checked out and latest information pulled down

git fetch --all
for branch in ${branches[@]}; do
    git checkout $branch
    git pull
done

# return to dev_2.0 branch
# checkout rules from each branch into _work folder

git checkout dev_2.0

for branch in ${branches[@]}; do
    if [[ ! -d "_work/$branch" ]]; then
        mkdir -p "_work/$branch"
    fi
    git --work-tree=_work/$branch checkout $branch -- rules

    git restore --staged .
done

# rename visionOS folder for simplicity

if [[ -d "_work/visionos_2.0" ]]; then
    rm -rf "_work/visionos_2.0"
fi

mv _work/visionos _work/visionos_2.0

# clone apple's device-management repo

# remove any existing version of apple repo and recreate
if [[ -d "_work/apple" ]]; then
    rm -rf "_work/apple"
fi

mkdir -p "_work/apple"

git clone https://github.com/apple/device-management "_work/apple"

exit 0
