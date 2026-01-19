ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

LIB = libadnsapi.a

CFLAGS += -I./ -O3 -ggdb3 -Wall
CFLAGS += -I$(ADNS_TRUNK)/include/common
CFLAGS += -I$(ADNS_TRUNK)/src/adns
CFLAGS += -I$(ADNS_TRUNK)/src/libadns
CFLAGS += -I$(ADNS_TRUNK)/src/adns_adm
CXXFLAGS = $(CFLAGS)
CXXFLAGS +=-I$(ADNS_TRUNK)/protobuf-3.5.1/target/include/
CXXFLAGS +=-I$(ADNS_TRUNK)/openssl-1.1.1b/target/include/

SRCS-y += adns_api_dispatch.cc
SRCS-y += adnsapi.pb.cc
SRCS-y += adns_api.c
SRCS-y += adns_api_params.cc
SRCS-y += rr_handlers.c
SRCS-y += zone_handlers.c

SRCS-y += domain_handlers.c
SRCS-y += refreshzone_handlers.c
SRCS-y += soasn_handlers.cc

SRCS-y += dnssec_handlers.cc

include $(RTE_SDK)/mk/rte.extlib.mk
export LD_LIBRARY_PATH=$(ADNS_TRUNK)/protobuf-3.5.1/target/lib:$LD_LIBRARY_PATH

reset:
	@rm -rf build
	@rm -f ./adnsapi.pb.h
	@rm -f ./adnsapi.pb.cc
	@$(ADNS_TRUNK)/protobuf-3.5.1/target/bin/protoc ./adnsapi.proto --cpp_out=./
	make clean
