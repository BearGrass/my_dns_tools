
ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-default-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = fwd_dns_dpdk

# all source are stored in SRCS-y
SRCS-y := fwd_dns.c
SRCS-y += daemon.c
SRCS-y += setup.c
SRCS-y += init.c
SRCS-y += user_config.c
SRCS-y += view.c
SRCS-y += tolower.c
SRCS-y += iplib.c
SRCS-y += view_maps.c
SRCS-y += msg.c
SRCS-y += runtime.c
SRCS-y += raw_input.c
SRCS-y += storage.c
SRCS-y += request.c
SRCS-y += admin.c
SRCS-y += ae.c
SRCS-y += anet.c
SRCS-y += networking.c
SRCS-y += stats.c
SRCS-y += qtype.c
SRCS-y += health_check.c
SRCS-y += man_whitelist.c
SRCS-y += man_blacklist.c
SRCS-y += ip_filter.c
SRCS-y += oversealist.c
SRCS-y += ipv6_fwd.c
SRCS-y += edns.c
SRCS-y += qos.c
SRCS-y += hijack.c
SRCS-y += adns_log.c
SRCS-y += dnscache_tbl.c
SRCS-y += dnscache.c
SRCS-y += fwd_user.c
SRCS-y += fwd_ip_user_tbl.c
SRCS-y += fwd_user_db.c
SRCS-y += snapshot.c

CFLAGS += -ggdb3 -O3 -Wall -fno-strict-aliasing
CFLAGS += -I$(LDNS_TRUNK)/include/common -I./
CFLAGS += -I$(LDNS_TRUNK)/include/datapath
CFLAGS += -I$(LDNS_TRUNK)/src/conhash

#CFLAGS += -I$(LDNS_TRUNK)/include/alisocket
CFLAGS += -I$(LDNS_TRUNK)/include/json-c

LDNS_LDLIBS += -lconhash -lfwd_dns_common -ljson-c -ldl

EXTRA_LDFLAGS += -L./ -L$(LDNS_TRUNK)/lib/ $(LDNS_LDLIBS)

# workaround for a gcc bug with noreturn attribute
ifeq ($(CONFIG_RTE_TOOLCHAIN_GCC),y)
CFLAGS_main.o += -Wno-return-type
endif

include $(RTE_SDK)/mk/rte.extapp.mk

reset:
	@rm -rf build
	@make clean

