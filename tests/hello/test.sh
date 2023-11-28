#!/bin/bash

pid=$(pidof hello)

[[ -z ${pid} ]] && echo "ERROR: Run ./hello first" && exit 1

make

upatch -p ${pid} --patch patch.up --log-level=9
cat /proc/${pid}/maps
