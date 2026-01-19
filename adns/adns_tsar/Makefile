DIRS = modules src adns_modules

all:
	for i in $(DIRS); do make -C $$i; done

clean:
	for i in $(DIRS); do cd $$i;make clean;cd ..; done

sources:
	git archive HEAD | gzip > adns_tsar.tar.gz

RPM:
	rm -rf /var/tmp/adns_tsar
	mkdir -p $(HOME)/rpmbuild/SOURCES
	cp adns_tsar.tar.gz $(HOME)/rpmbuild/SOURCES
	rpmbuild -bb adns_tsar.spec

install:
	#mkdir for adns_tsar
	mkdir -p /usr/local/adns_tsar/modules
	mkdir -p /etc/adns_tsar
	mkdir -p /usr/local/man/man8/
	mkdir -p /etc/adns_tsar/conf.d/
	#copy adns_tsar shared so
	cp modules/*.so /usr/local/adns_tsar/modules
	cp adns_modules/*.so /usr/local/adns_tsar/modules
	cp adns_modules/*.conf /etc/adns_tsar/conf.d/
	#copy bin file
	cp src/adns_tsar /usr/bin/adns_tsar
	#copy config file
	cp conf/adns_tsar.conf /etc/adns_tsar/adns_tsar.conf
	cp conf/adns_tsar.logrotate /etc/logrotate.d/adns_tsar
	cp conf/adns_tsar.cron /etc/cron.d/adns_tsar
	#copy man file
	cp conf/adns_tsar.8 /usr/local/man/man8/
	make -C adns_modules install

adns_tsardevel:
	mkdir -p /usr/local/adns_tsar/devel
	cp devel/mod_test.c /usr/local/adns_tsar/devel/mod_test.c
	cp devel/mod_test.conf /usr/local/adns_tsar/devel/mod_test.conf
	cp devel/adns_tsar.h /usr/local/adns_tsar/devel/adns_tsar.h
	cp devel/Makefile.test /usr/local/adns_tsar/devel/Makefile.test
	cp devel/adns_tsardevel /usr/bin/adns_tsardevel

uninstall:
	#rm adns_tsar
	rm -rf /usr/local/adns_tsar
	rm -rf /etc/adns_tsar/cron.d
	rm -f /etc/logrotate.d/adns_tsar
	rm -f /etc/cron.d/adns_tsar
	rm -f /usr/local/man/man8/adns_tsar.8
	#rm adns_tsar
	rm -f /usr/bin/adns_tsar
	#rm adns_tsardevel
	rm -f /usr/bin/adns_tsardevel
	#backup configure file
	mv /etc/adns_tsar/adns_tsar.conf /etc/adns_tsar/adns_tsar.conf.rpmsave
	make -C adns_modules uninstall

tags:
	ctags -R
	cscope -Rbq
