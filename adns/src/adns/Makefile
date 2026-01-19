ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-default-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = adns

# all source are stored in SRCS-y
#SRCS-y += ttt.c
SRCS-y += tcp_shm.c
#SRCS-y += ab_test.c
SRCS-y += adns.c
SRCS-y += adns_liba.c
SRCS-y += daemon.c
SRCS-y += setup.c
SRCS-y += init.c
SRCS-y += runtime.c
SRCS-y += msg.c
SRCS-y += adns_utili.c
SRCS-y += admin.c
#SRCS-y += adns_fdir.c
SRCS-y += init_zone.c
#SRCS-y += cksum.c
#SRCS-y += dns_pkt.c
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
SRCS-y += dnssec.c
SRCS-y += dnssec_cache.c
SRCS-y += dnssec_cache_msg.c

CFLAGS += -ggdb3 -O3 -Wall -fno-strict-aliasing
CFLAGS += -I$(ADNS_TRUNK)/include/common -I./
CFLAGS += -I$(ADNS_TRUNK)/include/datapath
CFLAGS += -I$(ADNS_TRUNK)/src/libadns
CFLAGS += -I$(ADNS_TRUNK)/src/ctrlplane
CFLAGS += -I$(ADNS_TRUNK)/protobuf-3.5.1/target/include
CFLAGS += -I$(ADNS_TRUNK)/src/ctrlplane
CFLAGS += -pthread
CFLAGS += -I$(ADNS_TRUNK)/openssl-1.1.1b/target/include

ifeq ($(GCOV_ENABLE), 1)
       CFLAGS += -ftest-coverage -fprofile-arcs
       CFLAGS += -lgcov
endif

ADNS_LDLIBS += -ladns_common
ADNS_LDLIBS += -ladns_dns
#ADNS_LDLIBS += -ladns_zscan
ADNS_LDLIBS += -lstdc++
ADNS_LDLIBS += -ladnsapi

EXTRA_LDFLAGS += -L./
EXTRA_LDFLAGS += -L/$(ADNS_TRUNK)/src/ctrlplane/build
EXTRA_LDFLAGS += $(ADNS_TRUNK)/openssl-1.1.1b/target/lib/libcrypto.a
EXTRA_LDFLAGS += $(ADNS_TRUNK)/openssl-1.1.1b/target/lib/libssl.a
EXTRA_LDFLAGS += $(ADNS_TRUNK)/protobuf-3.5.1/target/lib/libprotobuf.a
EXTRA_LDLIBS += $(ADNS_LDLIBS)


# workaround for a gcc bug with noreturn attribute
ifeq ($(CONFIG_RTE_TOOLCHAIN_GCC),y)
CFLAGS_main.o += -Wno-return-type
endif

include $(RTE_SDK)/mk/rte.extapp.mk

reset:
	@rm -rf build
	@make clean

install:
	@echo "INSTALL-APP $(APP)"
	@[ -d $(SRCDIR)/../../target/bin ] || mkdir -p $(SRCDIR)/../../target/bin
	@cp -f $(RTE_OUTPUT)/$(APP) $(SRCDIR)/../../target/bin
	@[ -d $(SRCDIR)/../../target/var/log ] || mkdir -p $(SRCDIR)/../../target/var/log
	@touch $(SRCDIR)/../../target/var/log/adns_query.log
	@touch $(SRCDIR)/../../target/var/log/adns_answer.log
