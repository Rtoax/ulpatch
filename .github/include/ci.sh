#!/bin/bash
set -e

BUILD_DIR="build-ci"

PIE=

__usage__()
{
	echo -e "
github-ci [options]

--pie=[ON|OFF]

-h, --help
" | more

	exit ${1-0}
}

TEMP=$(getopt \
	--options h \
	--long pie: \
	--long help \
	-n github-ci -- "$@")

test $? != 0 && __usage__ 1

eval set -- "$TEMP"

while true; do
	case $1 in
	--pie)
		shift
		PIE=$1
		shift
		;;
	-h|--help)
		shift
		__usage__
		;;
	--)
		shift
		break
		;;
	esac
done

cmake -B ${BUILD_DIR} ${PIE:+-DCONFIG_BUILD_PIE_EXE=${PIE}}

tree -d ${BUILD_DIR}
make -C ${BUILD_DIR} -j$(nproc)
sudo make -C ${BUILD_DIR} install

ulpatch --info
