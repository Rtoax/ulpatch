#!/bin/bash
sudo sh -c 'echo ./core.%p > /proc/sys/kernel/core_pattern'
ulimit -c unlimited
