
include $(RTE_SDK)/mk/rte.vars.mk

# Library name
LIB = libconhash.a

CFLAGS += -O0 -ggdb -Wall
CFLAGS += -I./

# all source are stored in SRCS-y
SRCS-y += conhash.c
SRCS-y += conhash_inter.c
SRCS-y += util_rbtree.c 
SRCS-y += conhash_util.c

# install this header file

# this lib needs eal
include $(RTE_SDK)/mk/rte.extlib.mk

