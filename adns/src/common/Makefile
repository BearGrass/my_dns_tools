
include $(RTE_SDK)/mk/rte.vars.mk

# Library name
LIB = libadns_common.a

CFLAGS += -ggdb3 -O3 -Wall
CFLAGS += -I$(ADNS_TRUNK)/include/common
CFLAGS += -I$(ADNS_TRUNK)/include/datapath
CFLAGS += -I./

ifeq ($(GCOV_ENABLE), 1)
       CFLAGS += -ftest-coverage -fprofile-arcs
       CFLAGS += -lgcov
endif

# all source are stored in SRCS-y
SRCS-y += cfg_file.c
SRCS-y += log.c
#SRCS-y += net_debug.c
SRCS-y += event.c
SRCS-y += net.c
#SRCS-y += ratelimit.c
SRCS-y += adns_counter.c

# install this header file

# this lib needs eal
include $(RTE_SDK)/mk/rte.extlib.mk

