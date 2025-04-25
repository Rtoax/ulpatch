#!/bin/bash
# Wrote by Rong Tao
set -e

PID=
GDB=$(which gdb 2>/dev/null || :)
ADDRESS=
return_size=64
verbose=

if [[ -z ${GDB} ]]; then
	echo >&2 "ERROR: Need gdb"
	exit 1
fi

if ! [[ " aarch64 x86_64 " =~ " $(uname -m) " ]]; then
	echo >&2 "ERROR: not support $(uname -m) yet"
	exit 1
fi

__usage__() {
	echo "
modify-return [-p <PID>] [--address=<ADDRESS>]

-p, --pid  [PID]        specify pid
-a, --address [ADDRESS] specify address to modify
-s, --size [32|64]      specify return size, default: ${return_size}

-v, --verbose           set -x
-h, --help              print this info
"
	exit ${1-0}
}

TEMP=$(getopt \
	--options p:a:s:vh \
	--long pid: \
	--long address: \
	--long size: \
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
	-s|--size)
		shift
		return_size=$1
		if ! [[ " 32 64 " =~ " ${return_size} " ]]; then
			echo >&2 "ERROR: return size only support 32|64"
			exit 1
		fi
		shift
		;;
	-v|--verbose)
		shift
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

[[ ${verbose} ]] && set -x

gdb_script_set=$(mktemp -u set-XXXX.gdb)

cleanup()
{
	rm -f ${gdb_script_set} 2>&1 >/dev/null
}
trap cleanup EXIT

case $(uname -m) in
aarch64)
	case ${return_size} in
	32)
		# return (int)false
		# 52800000 	mov	w0, #0x0                   	// #0
		# d65f03c0 	ret
		cat>>${gdb_script_set}<<-EOF
		set {unsigned long}${ADDRESS} = 0xd65f03c052800000
		EOF
		;;
	64)
		# return (long)false
		# d2800000 	mov	x0, #0x0                   	// #0
		# d65f03c0 	ret
		cat>>${gdb_script_set}<<-EOF
		set {unsigned long}${ADDRESS} = 0xd65f03c0d2800000
		EOF
		;;
	esac
	;;
x86_64)
	case ${return_size} in
	32 | 64)
		# return (int)false
		# b8 00 00 00 00       	mov    $0x0,%eax
		# c3                   	ret
		# 0xb800000000c30000
		# 0x00c30000b8000000
		cat>>${gdb_script_set}<<-EOF
		set {unsigned char}${ADDRESS} = 0xb8
		set {unsigned char}$(printf "0x%lx" $((${ADDRESS} + 0x1))) = 0x00
		set {unsigned char}$(printf "0x%lx" $((${ADDRESS} + 0x2))) = 0x00
		set {unsigned char}$(printf "0x%lx" $((${ADDRESS} + 0x3))) = 0x00
		set {unsigned char}$(printf "0x%lx" $((${ADDRESS} + 0x4))) = 0x00
		set {unsigned char}$(printf "0x%lx" $((${ADDRESS} + 0x5))) = 0xc3
		EOF
		;;
	esac
	;;
esac

gdb --quiet -p ${PID} < ${gdb_script_set} 2>&1 2>/dev/null

echo "WARNING: already write 'return false' to ${ADDRESS}"
