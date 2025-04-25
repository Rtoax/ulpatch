#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
set -e

git config core.hooksPath scripts/git/hooks/ 2>/dev/null
# This script called in top Makefile, need this 'get'.
git config get core.hooksPath 2>/dev/null || {
	# git version compat
	git config core.hooksPath 2>/dev/null
}
