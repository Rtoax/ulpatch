#!/bin/bash

make

upatch -p $(pidof hello) --patch patch.up --log-level=9
cat /proc/$(pidof hello)/maps
