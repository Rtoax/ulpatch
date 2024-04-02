#!/bin/bash

rpmbuild -ba \
	--define "_topdir $PWD" \
	--define "_sourcedir $PWD" \
	ulpatch.spec
