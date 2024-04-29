#!/bin/bash

if [[ ! -d .git/ ]]; then
	echo "ERROR: You are not in git tree."
	exit 1
fi

version=$(git describe --abbrev=0 --tags 2>/dev/null)
git archive --format tar.gz --prefix=ulpatch-${version}/ --output ulpatch-${version}.tar.gz master
