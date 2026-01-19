
all:
	make -C common
#	make -C zscan
	make -C libadns
	make -C adns_adm
	@rm -rf adns/build/
	@mkdir adns/build/
	make -C ctrlplane
#	@cp zscan/build/*.a adns/build/
	@cp common/build/*.a adns/build/
	@cp libadns/build/*.a adns/build/
ifeq ($(FUZZ), 1)
	make -C fuzz
else
	@rm -rf adns_liba/build/
	@mkdir adns_liba/build/
	make -C adns
	@cp -f libadns/dnskey.c adns_liba/
	@cp -f libadns/zone.c adns_liba/
	@cp -f adns/*.[ch] adns_liba/
	make -C adns_liba
endif

clean:
	make -C adns clean
	@rm -rf adns/build
	make -C libadns clean
	@rm -rf libadns/build
#	make -C zscan clean
#	@rm -rf zscan/build
	make -C common
	@rm -rf common/build
	make -C adns_adm clean
	make -C ctrlplane reset
	make -C fuzz clean
	@rm -f adns_liba/*.[ch]
	@rm -fr adns_liba/build/

install:
	make -C adns install
	make -C adns_adm install
	@[ -d $(CURDIR)/../target/scripts ] || mkdir -p $(CURDIR)/../target/scripts
	@[ -d $(CURDIR)/../target/kmod ] || mkdir -p $(CURDIR)/../target/kmod
	@cp -f ${RTE_SDK}/tools/* ../target/scripts
	@cp -f ${RTE_SDK}/${RTE_TARGET}/kmod/* ../target/kmod


