#!/bin/bash

# Use half of CPU cores
np=$(( $(nproc) / 2 ))

rpmbuild -ba \
	--define "_topdir $PWD" \
	--define "_sourcedir $PWD" \
	--define "_smp_mflags -j${np}" \
	ulpatch.spec
