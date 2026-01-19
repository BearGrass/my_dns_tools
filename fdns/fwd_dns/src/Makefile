
all:
	make -C common
	make -C conhash
	@rm -rf fwd_dns/build/
	@mkdir fwd_dns/build/
	@cp common/build/*.a fwd_dns/build/
	@cp conhash/build/*.a fwd_dns/build/
	make -C fwd_dns
	make -C fwd_dns/fwdctl clean
	make -C fwd_dns/fwdctl 
	make -C fwd_dns/aliss clean
	make -C fwd_dns/aliss
	if [ ! -e fwd_dns_bin/bin/ ] ; then  mkdir -p fwd_dns_bin/bin/ ; fi
	cp fwd_dns/build/app/fwd_dns_dpdk fwd_dns_bin/bin/
	cp fwd_dns/fwdctl/fwdctl fwd_dns_bin/bin/
	cp fwd_dns/aliss/aliss fwd_dns_bin/bin/ -f
rpm:
	make -C common
	make -C conhash
	@rm -rf fwd_dns/build/
	@mkdir fwd_dns/build/
	@cp common/build/*.a fwd_dns/build/
	@cp conhash/build/*.a fwd_dns/build/
	make -C fwd_dns
	make -C fwd_dns/fwdctl clean
	make -C fwd_dns/fwdctl 
	if [ ! -e fdns_run/bin/ ] ; then mkdir -p fdns_run/bin/ ; fi
	cp fwd_dns/build/app/fwd_dns_dpdk fdns_run/bin/
	cp fwd_dns/fwdctl/fwdctl fdns_run/bin/	

clean:
	make -C fwd_dns clean
	make -C fwd_dns/fwdctl clean
	@rm -rf fwd_dns/build
	make -C common clean
	@rm -rf common/build
	make -C conhash clean
	@rm -rf conhash/build

install:
	make -C fwd_dns install

