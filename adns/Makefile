MAKEFLAGS += --no-print-directory

export ADNS_TRUNK=$(CURDIR)
export ADNS_TARGET=/home/adns

ifeq ($(RTE_SDK),)
	RTE_SDK=$(CURDIR)/dpdk
endif
export RTE_SDK

ifeq ($(FUZZ), 1)
	export EXTRA_CFLAGS += -DFUZZ
endif
export FUZZ

ifeq ($(FUZZ), 1)
	RTE_TARGET=x86_64-native-linuxapp-clang
else
	RTE_TARGET=x86_64-native-linuxapp-gcc
endif
export RTE_TARGET

ifeq ($(40G), 1)
	export EXTRA_CFLAGS=-D__SUPPORT_NIC_XL710
	40G_Def = --define '_40g_opt 1'
else
	40G_Def = --define '_40g_opt 0'
endif

ifeq ($(MLX), 1)
	export EXTRA_CFLAGS=-D__SUPPORT_MLX
	MLX_Def = --define '_mlx_opt 1'
else
	MLX_Def = --define '_mlx_opt 0'
endif

ifeq ($(IPV6), 1)
	export EXTRA_CFLAGS += -D__IPV6_SUPPORT
	IPV6_Def = --define '_ipv6_opt 1'
else
	IPV6_Def = --define '_ipv6_opt 0'
endif

ifeq ($(PVT_ZONE), 1)
	export EXTRA_CFLAGS += -DPVT_ZONE
	PVTZ_Def = --define '_pvtz_opt 1'
else
	PVTZ_Def = --define '_pvtz_opt 0'
endif

all:
ifeq ($(FUZZ), 1)
	@echo -e "FUZZ test is ON.\n"
else
	@echo -e "FUZZ test is OFF.\n"
endif
ifeq ($(PVT_ZONE), 1)
	@echo -e "Private-zone mode is ON.\n"
else
	@echo -e "Private-zone mode is OFF.\n"
endif
ifeq ($(40G), 1)
	@echo -e "40G support is ON.\n"
else
	@echo -e "40G support is OFF.\n"
endif
ifeq ($(MLX), 1)
	@echo -e "Mellanox support is ON.\n"
else
	@echo -e "Mellanox support is OFF.\n"
endif
ifeq ($(IPV6), 1)
	@echo -e "ipv6 support is ON.\n"
else
	@echo -e "ipv6 support is OFF.\n"
endif
	@echo -e "ADNS TRUNK is $(ADNS_TRUNK).\n"
	@echo -e "RTE_TARGET is $(RTE_TARGET).\n"
	@echo -e "RTE_SDK is $(RTE_SDK).\n"
	make -C src
	make -C adns_tsar
	make liba
	make libopenssl


install: all
	make -C src install
ifeq ($(PACKAGING),)
	@mkdir -p $(ADNS_TARGET)/bin
	@mkdir -p $(ADNS_TARGET)/dump
	@mkdir -p $(ADNS_TARGET)/etc
	@mkdir -p $(ADNS_TARGET)/kmod
	@mkdir -p $(ADNS_TARGET)/scripts
	@mkdir -p $(ADNS_TARGET)/var/log
	@cp -rf target/* $(ADNS_TARGET)
	@echo -e "== Installed into $(ADNS_TARGET) ==\n"
endif

sources:
	git archive HEAD | gzip > adns-core.tar.gz

RPM_TOPDIR=$(HOME)/rpmbuild
rpm:
	rm -rf /var/tmp/adns
	rm -rf /var/tmp/dpdk
	rm -rf /var/tmp/adns_tsar
	mkdir -p $(HOME)/rpmbuild/SOURCES
	cp adns-core.tar.gz $(HOME)/rpmbuild/SOURCES
	
	rpmbuild -bb tools/rpm/adns.spec ${40G_Def} ${PVTZ_Def} ${IPV6_Def} 

clean:
	make -C src clean
	make -C adns_tsar clean
	@rm -rf target/bin/*
	@rm proclib/liba/lib*a -rf
	@rm /usr/local/lib64/libadns.a -f

.PHONY:liba
liba:
	@cp dpdk/x86_64-native-linuxapp-gcc/lib/* proclib/liba/ -f
	@cp src/common/build/lib/libadns_common.a proclib/liba/ -f
	@cp src/libadns/build/lib/libadns_dns.a	  proclib/liba/ -f
	@cp src/adns_liba/build/lib/libadns_app.a      proclib/liba/ -f
	@cp src/ctrlplane/build/lib/libadnsapi.a  proclib/liba/ -f
	@cd proclib/liba/  && ar -M <libaz.mri
	@[ -d ./target/bin ] || mkdir -p ./target/bin
	@cp proclib/liba/libadns.aaa target/bin/libadns.a -f

.PHONY:libopenssl
libopenssl:
	@cp openssl-1.1.1b/target/lib/libcrypto.a target/bin/libcrypto.a -f
	@cp openssl-1.1.1b/target/lib/libssl.a target/bin/libssl.a -f
