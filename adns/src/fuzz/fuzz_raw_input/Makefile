ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-default-linuxapp-gcc
export EXTRA_CFLAGS += -DFUZZ_RAW_INPUT

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = fuzz-raw-input
$(warning "######## making Fuzzing test for raw input ########")

# all source are stored in SRCS-y
SRCS-y += $(ADNS_TRUNK)/src/adns/adns.c
SRCS-y += $(ADNS_TRUNK)/src/adns/daemon.c
SRCS-y += $(ADNS_TRUNK)/src/adns/setup.c
SRCS-y += $(ADNS_TRUNK)/src/adns/init.c
SRCS-y += $(ADNS_TRUNK)/src/adns/runtime.c
SRCS-y += $(ADNS_TRUNK)/src/adns/msg.c
SRCS-y += $(ADNS_TRUNK)/src/adns/adns_utili.c
SRCS-y += $(ADNS_TRUNK)/src/adns/admin.c
#SRCS-y += adns_fdir.c
SRCS-y += $(ADNS_TRUNK)/src/adns/init_zone.c
#SRCS-y += cksum.c
#SRCS-y += dns_pkt.c
SRCS-y += $(ADNS_TRUNK)/src/adns/ae.c
SRCS-y += $(ADNS_TRUNK)/src/adns/anet.c
SRCS-y += $(ADNS_TRUNK)/src/adns/adns_log.c
SRCS-y += $(ADNS_TRUNK)/src/adns/networking.c
SRCS-y += $(ADNS_TRUNK)/src/adns/adns_sync.c
SRCS-y += $(ADNS_TRUNK)/src/adns/adns_stats.c
SRCS-y += $(ADNS_TRUNK)/src/adns/raw_input.c
SRCS-y += $(ADNS_TRUNK)/src/adns/ip_fragment.c
SRCS-y += $(ADNS_TRUNK)/src/adns/mbuf.c
SRCS-y += $(ADNS_TRUNK)/src/adns/mem_info.c
SRCS-y += $(ADNS_TRUNK)/src/adns/ring_list.c
SRCS-y += $(ADNS_TRUNK)/src/adns/rcu.c
SRCS-y += $(ADNS_TRUNK)/src/adns/dnssec.c

CFLAGS += -ggdb3 -Wall -fno-strict-aliasing
CFLAGS += -I$(ADNS_TRUNK)/include/common
CFLAGS += -I$(ADNS_TRUNK)/src/adns
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

EXTRA_LDFLAGS += -L$(ADNS_TRUNK)/src/adns/build
EXTRA_LDFLAGS += -L/$(ADNS_TRUNK)/src/ctrlplane/build
EXTRA_LDFLAGS += $(ADNS_TRUNK)/protobuf-3.5.1/target/lib/libprotobuf.a
EXTRA_LDFLAGS += $(ADNS_TRUNK)/openssl-1.1.1b/target/lib/libcrypto.a
EXTRA_LDFLAGS += $(ADNS_TRUNK)/openssl-1.1.1b/target/lib/libssl.a
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
