#!/bin/bash

version=$(git describe --abbrev=0 --tags 2>/dev/null)

git archive --format tar.gz --prefix=ulpatch-${version}/ --output ulpatch-${version}.tar.gz master
