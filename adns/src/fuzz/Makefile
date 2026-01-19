
all:
	@rm -rf fuzz_dns_parse/build/
	@mkdir fuzz_dns_parse/build/
	make -C fuzz_dns_parse
	@rm -rf fuzz_raw_input/build/
	@mkdir fuzz_raw_input/build/
	make -C fuzz_raw_input
	@rm -rf fuzz_dname_frm_str/build/
	@mkdir fuzz_dname_frm_str/build/
	make -C fuzz_dname_frm_str
	@rm -rf fuzz_dname_to_str/build/
	@mkdir fuzz_dname_to_str/build/
	make -C fuzz_dname_to_str
	@rm -rf fuzz_mm3_hash/build/
	@mkdir fuzz_mm3_hash/build/
	make -C fuzz_mm3_hash

clean:
	make -C fuzz_dns_parse clean
	@rm -rf fuzz_dns_parse/build
	make -C fuzz_raw_input clean
	@rm -rf fuzz_raw_input/build
	make -C fuzz_dname_frm_str clean
	@rm -rf fuzz_dname_frm_str/build
	make -C fuzz_dname_to_str clean
	@rm -rf fuzz_dname_to_str/build
	make -C fuzz_mm3_hash clean
	@rm -rf fuzz_mm3_hash/build

install:
	make -C adns install
	make -C adns_adm install
	@[ -d $(CURDIR)/../target/scripts ] || mkdir -p $(CURDIR)/../target/scripts
	@[ -d $(CURDIR)/../target/kmod ] || mkdir -p $(CURDIR)/../target/kmod
	@cp -f ${RTE_SDK}/tools/* ../target/scripts
	@cp -f ${RTE_SDK}/${RTE_TARGET}/kmod/* ../target/kmod


