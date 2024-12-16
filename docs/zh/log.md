
## 日志级别

参见 `syslog(2)` 手册或者头文件 `/usr/include/sys/syslog.h`。


## Syslog

日志将被记录在系统日志中。如果你的系统使用 `systemd` 作为服务管理器，你可以使用 `journalctl` 查看日志。


## ULPatch

每个 ULPatch 命令都包含参数 `--log-level[=LEVEL], --lv[=LEVEL]`, `--log-debug` 和 `--log-error` 参数来配置日志级别。日志级别遵循`/usr/include/sys/syslog.h`枚举值。你可以使用`-v, --verbose` 参数查看更多信息。

