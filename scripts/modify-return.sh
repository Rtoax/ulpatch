#!/bin/bash
# Wrote by Rong Tao
set -e

PID=
GDB=$(which gdb 2>/dev/null || :)
ADDRESS=

if [[ -z ${GDB} ]]; then
	echo >&2 "ERROR: Need gdb"
	exit 1
fi

if [[ $(uname -m) != aarch64 ]]; then
	echo >&2 "ERROR: only support aarch64, not support $(uname -m) yet"
	exit 1
fi

usage()
{
	echo "
modify-address.sh <PID> <ADDRESS>
"
}

PID=$1
shift 1
ADDRESS=$1

if [[ -z ${PID} ]]; then
	usage
	echo >&2 "ERROR: Need pass PID"
	exit 1
fi

if [[ -z ${ADDRESS} ]] || [[ ${ADDRESS:0:2} != 0x ]]; then
	usage
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
