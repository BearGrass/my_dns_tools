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

RPM_TOPDIR=$(HOME)/rpmbuild
rpm:
	rm -rf /var/tmp/dnsmega
	cp -a ../dns_defender /var/tmp
	cp -a misc/rpm/dnsmega.spec $(RPM_TOPDIR)/SPECS
	rpmbuild -bb $(RPM_TOPDIR)/SPECS/dnsmega.spec
