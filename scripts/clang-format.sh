#!/bin/bash
# Check code format with clang-format.
#
# Usage: [FCF=1] [FORCE=1] clang-format.sh
# - FORCE/FCF: Force mode of Clang-Format
#
set -e

[[ -z ${FCF} ]] && FCF=${FORCE}

fatal() {
	echo >&2 -en "\033[31m"
	echo >&2 -e "FATAL: "${@}
	echo >&2 -en "\033[0m"
	if [[ -z ${FCF} ]]; then
		echo >&2 "WARNING: skip this error with env FCF=1 or FORCE=1"
		exit 1
	fi
}

readonly GIT_TOPDIR=$(git rev-parse --show-toplevel 2>/dev/null || :)

# Check code format wich git-clang-format
readonly clang_format=$(which git-clang-format 2>/dev/null || :)

if  [[ -z ${clang_format} ]]; then
	fatal "Not found git-clang-format, please install"
fi

repository=$(basename ${GIT_TOPDIR})
if [[ " ostools tools ulpatch " =~ " ${repository} " ]]; then
	branch=origin/master
elif [[ " test-linux tst-linux " =~ " ${repository} " ]]; then
	branch=origin/main
else
	fatal "Unknown repository '${repository}', please modify ${0}!"
fi
c_patch="$( ${clang_format} --diff ${branch} --extensions c,cpp,cu,h,hpp | \
		grep -v -e 'no modified files to format' \
			-e 'clang-format did not modify any files' || :)"
if [[ $? != 0 ]] || [[ "${c_patch}" ]]; then
	echo "${c_patch}"
	fatal "Bad code format, please modify according to the above diff"
fi

exit 0
