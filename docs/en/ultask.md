
## ULTask Introduction

You could see the [theory](./THEORY.md) first, and **man ultask** is also helpful.


## Common Arguments

The `--pid` parameter must be specified, passing in a valid process **PID**.
`--log-level|--lv=debug,dbg,info,inf,notice,note,warning,warn,error,err,crit,alert,emerg` to set log level.


## Informations

- Use `--vmas` to display the VMA information of the target process.
- Use `--threads` to display thread information for the target process.
- Use `--fds` to display the file descriptor information for the target process.
- Use `--auxv` to display auxiliary vector information for the target process.
- Use `--status` to display the status information of the target process.
- Use `--syms|--symbols` to display the ELF symbol information of the target process.


## Dump

Use `--dump` to dump the target process.


## Jump

Using `--jmp` to modify a snippet of code to jump from one address to another is dangerous, and **it's best not to do it unless you know what you're doing**.


## Mapping

Use `--map` to map a file to the target process. This parameter and `--unmap` are a pair.


## Protection of a region of memory

Use `--mprotect` to modify the memory of the target process address space.
