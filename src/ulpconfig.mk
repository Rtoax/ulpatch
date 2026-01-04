# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025-2026 Rong Tao
ULPCONFIG_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
ULPCONFIG :=

ifndef ULPCONFIG
  ULPCONFIG := $(shell which ulpconfig 2>/dev/null)
  ifeq (${ULPCONFIG},)
    ULPCONFIG := ${ULPCONFIG_DIR}/ulpconfig.sh.in
  endif
endif

ifeq ($(wildcard ${ULPCONFIG}),)
  $(error Not found ulpconfig in any where)
endif

ifdef DEBUG
  $(info ULPCONFIG = ${ULPCONFIG})
endif
