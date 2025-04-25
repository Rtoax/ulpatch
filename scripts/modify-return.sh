#!/bin/bash
# Wrote by Rong Tao
set -e

PID=
GDB=$(which gdb 2>/dev/null || :)
ADDRESS=
verbose=

if [[ -z ${GDB} ]]; then
	echo >&2 "ERROR: Need gdb"
	exit 1
fi

if [[ $(uname -m) != aarch64 ]]; then
	echo >&2 "ERROR: only support aarch64, not support $(uname -m) yet"
	exit 1
fi

__usage__() {
	echo "
modify-return [-p <PID>] [--address <ADDRESS>]

-p, --pid  [PID]        specify pid
-a, --address [ADDRESS] specify address to modify
-v, --verbose           set -x
-h, --help              print this info
"
	exit ${1-0}
}

TEMP=$(getopt \
	--options p:a:vh \
	--long pid: \
	--long address: \
	--long verbose \
	--long help \
	-n modify-return -- "$@")

test $? != 0 && __usage__ 1

eval set -- "$TEMP"

while true; do
	case $1 in
	-p|--pid)
		shift
		PID=$1
		if ! [[ -d /proc/${PID} ]]; then
			echo >&2 "ERROR: PID=${PID} is not exist."
			exit 1
		fi
		shift
		;;
	-a|--address)
		shift
		ADDRESS=$1
		shift
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

if [[ -z ${PID} ]]; then
	__usage__
	echo >&2 "ERROR: Need pass PID"
	exit 1
fi

if [[ -z ${ADDRESS} ]] || [[ ${ADDRESS:0:2} != 0x ]]; then
	__usage__
	echo >&2 "ERROR: Must pass a address with 0x prefix"
	exit 1
fi

gdb_script_set=$(mktemp -u set-XXXX.gdb)

cleanup()
{
	rm -f ${gdb_script_set}
}
trap cleanup EXIT

# return (int)false
# 52800000 	mov	w0, #0x0                   	// #0
# d65f03c0 	ret
# return (long)false
# d2800000 	mov	x0, #0x0                   	// #0
# d65f03c0 	ret
cat>>${gdb_script_set}<<EOF
set {unsigned long}${ADDRESS} = 0xd2800000d65f03c0
EOF

gdb --quiet -p ${PID} < ${gdb_script_set} 2>&1 2>/dev/null

echo "WARNING: already write 'return false' to ${ADDRESS}"
