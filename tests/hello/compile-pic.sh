#!/bin/bash
make clean
make ULP_PIC=1 "$@"
