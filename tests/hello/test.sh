#!/bin/bash
set -e

pid=
patch=
debug=

__usage__() {
	echo "
test [-h|--help] [-u|--patch]

-p, --pid  [PID]        specify pid
-u, --patch [ULPATCH]    specify ulpatch file

-d, --debug             debug mode

-h, --help              print this info
"
	exit ${1-0}
}

TEMP=$(getopt \
	--options p:u:dh \
	--long pid: \
	--long patch: \
	--long debug \
	--long help \
	-n ulpatch-hello-test -- "$@")

test $? != 0 && __usage__ 1

eval set -- "$TEMP"

while true; do
	case $1 in
	-p|--pid)
		shift
		pid=$1
		shift
		;;
	-u|--patch)
		shift
		patch=$1
		shift
		;;
	-d|--debug)
		shift
		debug=$1
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

[[ -z ${pid} ]] && pid=$(pidof hello || true)
[[ -z ${pid} ]] && pid=$(pidof hello-pie || true)
[[ -z ${pid} ]] && echo "ERROR: Run ./hello or ./hello-pie first or specify -p" && exit 1

[[ -z ${patch} ]] && echo "ERROR: Must specify ulpatch with -u" && exit 1
[[ ! -e ${patch} ]] && echo "ERROR: ${patch} is not exist." && exit 1

make

ulpatch -p ${pid} --patch ${patch} ${debug:+--log-level=9}
cat /proc/${pid}/maps
ulpinfo -p ${pid} ${debug:+--log-level=9}

dump_all_process_ulpatch() {
	local patches_addr_range=( $(cat /proc/${pid}/maps | grep patch- | awk '{print $1}') )

	for ((i = 0; i < ${#patches_addr_range[@]}; i++))
	do
		rm -f patch-$i.ulp
		ultask -p ${pid} --dump-vma ${patches_addr_range[$i]} -o patch-$i.ulp
	done
}
dump_all_process_ulpatch
