#!/bin/bash

ELF="./hello"

if [[ $# == 0 ]]; then
	echo "Usage: $0 [hello|hello-pie]"
else
	ELF="./$1"
fi

sudo bpftrace -e \
	"uprobe:${ELF}:print_hello {
		printf(\"%-8d %-16s %-16lx\n\", tid, comm, uaddr(\"print_hello\"));
	}"
