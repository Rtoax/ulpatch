#!/bin/bash
# Wrote by Rong Tao
set -e

PID=
EXE=
GDB=$(which gdb 2>/dev/null || :)
FUNCTION=
ADDRESS=
return_size=64
return_neg_1011=
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
modify-return [-p <PID>] [--function <FUNCTION>] [--address=<ADDRESS>]

-p, --pid  [PID]        specify pid
-f, --function [FUNC]   specify function name
-a, --address [ADDRESS] specify address to modify
-s, --size [32|64]      specify return size, default: ${return_size}

--return-neg-1011       return (-1011)

-v, --verbose           set -x
-h, --help              print this info
"
	exit ${1-0}
}

TEMP=$(getopt \
	--options p:f:a:s:vh \
	--long pid: \
	--long function: \
	--long address: \
	--long size: \
	--long return-neg-1011 \
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
		EXE=$(sudo readlink /proc/${PID}/exe)
		shift
		;;
	-f|--function)
		shift
		FUNCTION=$1
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
	--return-neg-1011)
		shift
		return_neg_1011=YES
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

if [[ ${FUNCTION} ]] && [[ ${ADDRESS} ]]; then
	echo >&2 "ERROR: Only specify one of --function or --address"
	exit 1
fi

[[ ${verbose} ]] && set -x

gdb_script_func_address=$(mktemp -u func_addr-XXXX.gdb)
gdb_script_set=$(mktemp -u set-XXXX.gdb)

cleanup()
{
	rm -f ${gdb_script_set} ${gdb_script_func_address} 2>&1 >/dev/null
}
trap cleanup EXIT


if [[ ${FUNCTION} ]]; then
	cat>>${gdb_script_func_address}<<-EOF
	info address ${FUNCTION}
	EOF

	ADDRESS=$(gdb --quiet -p ${PID} < ${gdb_script_func_address} | \
			grep -ow -E 'at 0x[0-9a-fA-F]*?' | \
			awk '{print $2}' | \
			tail -n1)

	if [[ -z ${ADDRESS} ]]; then
		echo >&2 "ERROR: Not found symbol ${FUNCTION} in ${EXE}"
		exit 1
	fi
fi

if [[ -z ${ADDRESS} ]] || [[ ${ADDRESS:0:2} != 0x ]]; then
	__usage__
	echo >&2 "ERROR: Must pass a address with 0x prefix"
	exit 1
fi

case $(uname -m) in
aarch64)
	value=
	case ${return_size} in
	32)
		if [[ ${return_neg_1011} ]]; then
			# return (int)-1011
			# 12807e40 	mov	w0, #0xfffffc0d            	// #-1011
			# d65f03c0 	ret
			value=0xd65f03c012807e40
		else
			# return (int)false
			# 52800000 	mov	w0, #0x0                   	// #0
			# d65f03c0 	ret
			value=0xd65f03c052800000
		fi
		;;
	64)
		if [[ ${return_neg_1011} ]]; then
			# return (long)-1011
			# 92807e40 	mov	x0, #0xfffffffffffffc0d    	// #-1011
			# d65f03c0 	ret
			value=0xd65f03c092807e40
		else
			# return (long)false
			# d2800000 	mov	x0, #0x0                   	// #0
			# d65f03c0 	ret
			value=0xd65f03c0d2800000
		fi
		;;
	esac
	cat>>${gdb_script_set}<<-EOF
	set {unsigned long}${ADDRESS} = ${value}
	EOF
	;;
x86_64)
	case ${return_size} in
	32 | 64)
		if [[ ${return_neg_1011} ]]; then
			if [[ ${return_size} == 32 ]]; then
				# return (int)-1011
				# b8 0d fc ff ff       	mov    $0xfffffc0d,%eax
				# c3                   	ret
				cat>>${gdb_script_set}<<-EOF
				set {unsigned char}${ADDRESS} = 0xb8
				set {unsigned char}$(printf "0x%lx" $((${ADDRESS} + 0x1))) = 0x0d
				set {unsigned char}$(printf "0x%lx" $((${ADDRESS} + 0x2))) = 0xfc
				set {unsigned char}$(printf "0x%lx" $((${ADDRESS} + 0x3))) = 0xff
				set {unsigned char}$(printf "0x%lx" $((${ADDRESS} + 0x4))) = 0xff
				set {unsigned char}$(printf "0x%lx" $((${ADDRESS} + 0x5))) = 0xc3
				EOF
			else
				# return (long)-1011
				# 48 c7 c0 0d fc ff ff 	mov    $0xfffffffffffffc0d,%rax
				# c3                   	ret
				cat>>${gdb_script_set}<<-EOF
				set {unsigned char}${ADDRESS} = 0x48
				set {unsigned char}$(printf "0x%lx" $((${ADDRESS} + 0x1))) = 0xc7
				set {unsigned char}$(printf "0x%lx" $((${ADDRESS} + 0x2))) = 0xc0
				set {unsigned char}$(printf "0x%lx" $((${ADDRESS} + 0x3))) = 0x0d
				set {unsigned char}$(printf "0x%lx" $((${ADDRESS} + 0x4))) = 0xfc
				set {unsigned char}$(printf "0x%lx" $((${ADDRESS} + 0x5))) = 0xff
				set {unsigned char}$(printf "0x%lx" $((${ADDRESS} + 0x6))) = 0xff
				set {unsigned char}$(printf "0x%lx" $((${ADDRESS} + 0x7))) = 0xc3
				EOF
			fi
		else
			# return (long)false
			# b8 00 00 00 00       	mov    $0x0,%eax
			# c3                   	ret
			cat>>${gdb_script_set}<<-EOF
			set {unsigned char}${ADDRESS} = 0xb8
			set {unsigned char}$(printf "0x%lx" $((${ADDRESS} + 0x1))) = 0x00
			set {unsigned char}$(printf "0x%lx" $((${ADDRESS} + 0x2))) = 0x00
			set {unsigned char}$(printf "0x%lx" $((${ADDRESS} + 0x3))) = 0x00
			set {unsigned char}$(printf "0x%lx" $((${ADDRESS} + 0x4))) = 0x00
			set {unsigned char}$(printf "0x%lx" $((${ADDRESS} + 0x5))) = 0xc3
			EOF
		fi
		;;
	esac
	;;
esac

gdb --quiet -p ${PID} < ${gdb_script_set} 2>&1 2>/dev/null

echo "WARNING: already write 'return false' to ${ADDRESS}"
