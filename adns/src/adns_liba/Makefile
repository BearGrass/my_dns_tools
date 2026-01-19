
include $(RTE_SDK)/mk/rte.vars.mk

# library name
LIB = libadns_app.a
export EXTRA_CFLAGS += -DADNS_LIBA
CFLAGS += -ggdb3 -O3 -Wall
#CFLAGS += -I./
#CFLAGS += -I$(ADNS_TRUNK)/include/common

# all source are stored in SRCS-y
SRCS-y += tcp_shm.c
SRCS-y += adns_liba.c
SRCS-y += daemon.c
SRCS-y += setup.c
SRCS-y += init.c
SRCS-y += runtime.c
SRCS-y += msg.c
SRCS-y += adns_utili.c
SRCS-y += admin.c
SRCS-y += init_zone.c
SRCS-y += ae.c
SRCS-y += anet.c
SRCS-y += adns_log.c
SRCS-y += networking.c
SRCS-y += adns_sync.c
SRCS-y += adns_stats.c
SRCS-y += raw_input.c
SRCS-y += ip_fragment.c
SRCS-y += mbuf.c
SRCS-y += mem_info.c
SRCS-y += ring_list.c
SRCS-y += rcu.c
SRCS-y += dnskey.c
SRCS-y += dnssec.c
SRCS-y += dnssec_cache.c
SRCS-y += dnssec_cache_msg.c
SRCS-y += zone.c


CFLAGS += -ggdb3 -O3 -Wall -fno-strict-aliasing
CFLAGS += -I$(ADNS_TRUNK)/include/common -I./
CFLAGS += -I$(ADNS_TRUNK)/include/datapath
CFLAGS += -I$(ADNS_TRUNK)/src/libadns
CFLAGS += -I$(ADNS_TRUNK)/src/ctrlplane
CFLAGS += -I$(ADNS_TRUNK)/protobuf-3.5.1/target/include
CFLAGS += -I$(ADNS_TRUNK)/openssl-1.1.1b/target/include
CFLAGS += -I$(ADNS_TRUNK)/src/ctrlplane
CFLAGS += -pthread


# this lib needs eal
include $(RTE_SDK)/mk/rte.extlib.mk

