ifeq ($(ASMEGA_TARGET),)
ASMEGA_TARGET=/var/dns/asmega
endif

export DNS_TRUNK=$(CURDIR)

all:
	make -C src
clean:
	make -C src clean
	rm -rf target/bin/*
	rm -rf target/lib/*
	rm -rf target/modules/*
	rm -rf target/script/*
install:
	make -C src install
	@mkdir -p $(ASMEGA_TARGET)/bin
	@mkdir -p $(ASMEGA_TARGET)/lib
	@mkdir -p $(ASMEGA_TARGET)/dump
	@mkdir -p $(ASMEGA_TARGET)/etc
	@mkdir -p $(ASMEGA_TARGET)/kmod
	@mkdir -p $(ASMEGA_TARGET)/scripts
	@mkdir -p $(ASMEGA_TARGET)/var/log
	@touch $(ASMEGA_TARGET)/var/log/asmega_adm.log
	@chmod 666 $(ASMEGA_TARGET)/var/log/asmega_adm.log
	@cp -rf target/* $(ASMEGA_TARGET)
	@echo -e "== Installed into $(ASMEGA_TARGET) ==\n"

RPM_TOPDIR=$(HOME)/rpmbuild
rpm:
	rm -rf /var/tmp/asmega
	cp -a ../asmega /var/tmp
	cp -a misc/rpm/asmega.spec $(RPM_TOPDIR)/SPECS
	rpmbuild -bb $(RPM_TOPDIR)/SPECS/asmega.spec
