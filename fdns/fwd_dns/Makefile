
MAKEFLAGS += --no-print-directory

export LDNS_TRUNK=$(CURDIR)

ifeq ($(RTE_SDK),)
	RTE_SDK=$(CURDIR)/../dpdk
endif
export RTE_SDK

ifeq ($(RTE_RTE_TARGET),)
	RTE_TARGET=x86_64-native-linuxapp-gcc
endif
export RTE_TARGET

ifeq ($(40G), 1)
	export EXTRA_CFLAGS=-D__SUPPORT_NIC_XL710
endif

ifeq ($(IPV6), 1)
	export EXTRA_CFLAGS += -D__IPV6_SUPPORT
endif


all:
	make -C src

clean:
	make -C src clean
	@rm -rf target/bin/*

install:
	make -C src install

rpm:
	rm ~/tmp/fdns -rf
	if [ ! -d ~/tmp ]; then mkdir ~/tmp/; fi; \
	cp -rf ../../fdns ~/tmp
	cd ~/tmp/fdns/fwd_dns/src/; \
	sh build_rpm.sh ~/tmp/fdns

