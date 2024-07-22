#!/bin/bash

ELF="./hello"

if [[ $# == 0 ]]; then
	echo "Usage: $0 [hello|hello-pie]"
else
	ELF="./$1"
fi

sudo bpftrace -e "uprobe:${ELF}:print_hello { printf(\"%-8d %s\n\", tid, comm); }"
