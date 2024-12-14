#!/bin/bash

if [[ ! -d .git/ ]]; then
	echo "ERROR: You are not in git tree." >&2
	exit 1
fi

if [[ ${VERSION} ]]; then
	version=${VERSION}
else
	version=$(git describe --abbrev=0 --tags 2>/dev/null)
fi
name=ulpatch-${version}
git archive --format tar.gz --prefix=${name}/ --output ${name}.tar.gz master
