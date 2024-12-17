#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2024 Rong Tao
#
set -e

pid=
patch=
unpatch=
debug=
error=
verbose=

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
		verbose=yes
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
	ulpatch -p ${pid} --patch ${patch} ${debug:+--lv=dbg} ${verbose:+-v} ${error:+--lv=err}
fi
if [[ ${unpatch} ]]; then
	ulpatch -p ${pid} --unpatch ${debug:+--lv=dbg} ${error:+--lv=err} ${verbose:+-v}
fi

# Disasm print_hello
print_hello_addr=$(ultask -p ${pid} --sym | grep -w print_hello | awk '{print $3}')
ultask -p ${pid} --dump disasm,addr=${print_hello_addr},size=16

cat /proc/${pid}/maps
ulpinfo -p ${pid} ${debug:+--lv=dbg} ${error:+--lv=err} ${verbose:+-vvv}

dump_all_process_ulpatch() {
	local range_addrs=( $(cat /proc/${pid}/maps \
				| grep $(ulpatch --map-pfx) \
				| awk '{print $1}') )

	for ((i = 0; i < ${#range_addrs[@]}; i++))
	do
		rm -f patch-$i.ulp
		ultask -p ${pid} --dump vma,addr=${range_addrs[$i]} -o patch-$i.ulp
	done
}
dump_all_process_ulpatch
