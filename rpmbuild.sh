#!/bin/bash

# Use half of CPU cores
np=$(( $(nproc) / 2 ))

nodebuginfo=

__usage__() {
	echo -e "
--nodebuginfo   skip debuginfo and debugsource packages
-h, --help      print this info
"
	exit ${1-0}
}

TEMP=$( getopt --options h \
	--long help \
	--long nodebuginfo \
	--name rpmbuild-ulpatch -- "$@" )
test $? != 0 && __usage__ 1

eval set -- "${TEMP}"

while true ; do
	case $1 in
	-h | --help)
		shift
		__usage__
		;;
	--nodebuginfo)
		shift
		nodebuginfo=YES
		;;
	--)
		shift
		break
		;;
	esac
done

rpmbuild -ba \
	--define "_topdir $PWD" \
	--define "_sourcedir $PWD" \
	--define "_smp_mflags -j${np}" \
	${nodebuginfo:+--nodebuginfo} \
	ulpatch.spec
