#!/bin/bash
set -e

if [[ ! -d .git/ ]]; then
	echo "WARNING: You are not in git tree." >&2
	set -x
fi

version=${VERSION}
gitversion=$(git describe --abbrev=0 --tags 2>/dev/null || true)
specversion=v$(rpmspec -q --qf "%{version}\n" ulpatch.spec | head -n1)

# Read version from ulpatch.spec, cause, in github workflow, there is no .git/
# exist anywhere.
[[ -z ${version} ]] && version=${gitversion}
[[ -z ${version} ]] && version=${specversion}

[[ -z ${version} ]] && echo "ERROR: Couldn't found version anywhere!!!" && exit 1

name=ulpatch-${version}

# Use git repo first
if [[ -d .git/ ]]; then
	git archive --format tar.gz --prefix=${name}/ --output ${name}.tar.gz master
else
	rm -rf build/ build-ci/ #${name}
	#ln -s . ${name}
	tar -czf ${name}.tar.gz --transform "s|^|${name}/|" --dereference *
fi
