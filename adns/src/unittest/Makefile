export PWD = $(shell pwd)
export DPDK_PATH        = $(PWD)/../../dpdk/x86_64-native-linuxapp-gcc
export DPDK_INC_PATH    = $(DPDK_PATH)/include
export DPDK_LIB_PATH    = $(DPDK_PATH)/lib

export RTE_SDK          = $(PWD)/../../dpdk
export RTE_TARGET       = x86_64-native-linuxapp-gcc


UT_PRIVATE_ROUTE        = ut_private_route


all:
	$(MAKE)     -C  $(UT_PRIVATE_ROUTE)

.PHONY: env

env:
	mkdir -p /tmp/libdpdk
	rm -rf /tmp/libdpdk/*
	cp -rf ${RTE_SDK}/x86_64-native-linuxapp-gcc/lib/*.a /tmp/libdpdk
	cd /tmp/libdpdk;for i in `ls *.a`;do ar x $$i;done;cd -
	mkdir -p libdpdk;rm -rf libdpdk/*
	ar rs libdpdk/libdpdk.a /tmp/libdpdk/*.o
	

.PHONY: clean

clean:
	$(MAKE)		-C	$(UT_PRIVATE_ROUTE)		clean	
