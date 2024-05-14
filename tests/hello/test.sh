#!/bin/bash
set -e

pid=
patch=
unpatch=
debug=
error=

__usage__() {
	echo "
test [-h|--help] [-u|--patch]

-p, --pid  [PID]        specify pid
-u, --patch [ULPATCH]   specify ulpatch file
    --unpatch           unpatch a ulpatch
-d, --debug             debug mode for ulpatch
    --error             error mode
-v, --verbose           set -x
-h, --help              print this info
"
	exit ${1-0}
}

TEMP=$(getopt \
	--options p:u:dvh \
	--long pid: \
	--long patch: \
	--long unpatch \
	--long debug \
	--long error \
	--long verbose \
	--long help \
	-n ulpatch-tests-hello -- "$@")

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
	--unpatch)
		shift
		unpatch=yes
		;;
	-d|--debug)
		shift
		debug=$1
		;;
	--error)
		shift
		error=$1
		;;
	-v|--verbose)
		shift
		set -x
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

[[ -z ${pid} ]] && pid=( $(pidof hello hello-pie || true) )
[[ -z "${pid}" ]] && echo "ERROR: Run ./hello or ./hello-pie first or specify -p" && exit 1
[[ ${#pid[@]} -gt 1 ]] && echo "ERROR: too much processes are running." && exit 1

if [[ -z ${patch} ]] && [[ -z ${unpatch} ]]; then
	echo "ERROR: Must specify ulpatch with -u or specify --unpatch" && exit 1
fi
if [[ ! -z ${patch} ]] && [[ ! -e ${patch} ]]; then
	echo "ERROR: ${patch} is not exist." && exit 1
fi

make

if [[ ${patch} ]]; then
	ulpatch -p ${pid} --patch ${patch} ${debug:+--log-level=9 -v} ${error:+--lv=err -v}
fi
if [[ ${unpatch} ]]; then
	ulpatch -p ${pid} --unpatch ${debug:+--log-level=9 -v} ${error:+--lv=err -v}
fi

cat /proc/${pid}/maps
ulpinfo -p ${pid} ${debug:+--log-level=9 -v} ${error:+--lv=err -v}

dump_all_process_ulpatch() {
	local patches_addr_range=( $(cat /proc/${pid}/maps | grep patch- | awk '{print $1}') )

	for ((i = 0; i < ${#patches_addr_range[@]}; i++))
	do
		rm -f patch-$i.ulp
		ultask -p ${pid} --dump-vma ${patches_addr_range[$i]} -o patch-$i.ulp
	done
}
dump_all_process_ulpatch
