
## Log Level

See syslog(2) manual or file `/usr/include/sys/syslog.h`.


## Syslog

The important logs will be recorded in to system log. If your system use `systemd` as service manager, you can use `journalctl`.


## ULPatch

Each ULPatch command has `--log-level[=LEVEL], --lv[=LEVEL]`, `--log-debug` and `--log-error` arguments, use to specify log level. The log level number obey `/usr/include/sys/syslog.h` rules. And you could use `-v, --verbose` argument to see more informations.
