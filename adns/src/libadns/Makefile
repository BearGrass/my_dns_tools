
include $(RTE_SDK)/mk/rte.vars.mk

# Library name
LIB = libadns_dns.a

CFLAGS += -ggdb3 -O3 -Wall
CFLAGS += -I./
CFLAGS += -I$(ADNS_TRUNK)/include/common
CFLAGS += -I$(ADNS_TRUNK)/openssl-1.1.1b/target/include

ifeq ($(GCOV_ENABLE), 1)
       CFLAGS += -ftest-coverage -fprofile-arcs
       CFLAGS += -lgcov
endif

# all source are stored in SRCS-y
SRCS-y += murmurhash3.c
SRCS-y += rrset.c
SRCS-y += node.c
SRCS-y += zone.c
SRCS-y += zonedb.c
SRCS-y += dname.c
SRCS-y += consts.c
SRCS-y += view_maps.c
SRCS-y += iplib.c
SRCS-y += domain_hash.c
#SRCS-y += edns.c
SRCS-y += tolower.c
SRCS-y += private_route.c
SRCS-y += qps_limit.c
SRCS-y += dnskey.c

# install this header file

# this lib needs eal
include $(RTE_SDK)/mk/rte.extlib.mk

