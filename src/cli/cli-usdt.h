#include <string.h>

#include <utils/util.h>

#include <utils/trace.h>


// sudo bpftrace -e 'usdt:./src/elftools:cli:elf_load{printf("%s %s\n", probe, str(arg0));}'
#define trace_cli_elf_load(path) \
	__trace_cli_probe_s1(cli, elf_load, path)

// sudo bpftrace -e 'usdt:./src/elftools:cli:elf_delete{printf("%s %s\n", probe, str(arg0));}'
#define trace_cli_elf_delete(path) \
	__trace_cli_probe_s1(cli, elf_delete, path)

// sudo bpftrace -e 'usdt:./src/elftools:cli:elf_select{printf("%s %s\n", probe, str(arg0));}'
#define trace_cli_elf_select(path) \
	__trace_cli_probe_s1(cli, elf_select, path)

// sudo bpftrace -e 'usdt:./src/elftools:cli:elf_list{printf("%s\n", probe);}'
#define trace_cli_elf_list() \
	__trace_cli_probe0(cli, elf_list)

#define trace_cli_client_list() \
	__trace_cli_probe0(cli, client_list)

// sudo bpftrace -e 'usdt:./src/elftools:cli:shell{printf("%s %s\n", probe, str(arg0));}'
#define trace_cli_shell(command) \
	__trace_cli_probe_s1(cli, shell, command)

