
include $(RTE_SDK)/mk/rte.vars.mk

# Library name
LIB = libfwd_dns_common.a

CFLAGS += -O3 -ggdb -Wall
CFLAGS += -I$(LDNS_TRUNK)/include/common
CFLAGS += -I$(LDNS_TRUNK)/include/datapath
CFLAGS += -I./

# all source are stored in SRCS-y
SRCS-y += cfg_file.c
SRCS-y += log.c
SRCS-y += net_debug.c
SRCS-y += event.c
SRCS-y += bit.c
#SRCS-y += adns_fdir.c
SRCS-y += common.c
SRCS-y += net.c
SRCS-y += time_nosc.c

# install this header file

# this lib needs eal
include $(RTE_SDK)/mk/rte.extlib.mk

