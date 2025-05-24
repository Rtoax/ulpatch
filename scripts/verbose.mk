ifeq ($(V),1)
  Q =
  MAKEFLAGS += V=1
else
  Q = @
  MAKEFLAGS += --silent
  MAKEFLAGS += --no-print-directory
endif
