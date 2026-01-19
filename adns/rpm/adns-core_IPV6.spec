
%define major_version 2
%define minor_version 19
%if 0%{?_40g_opt > 0}
%define nic _40G
%endif
%if 0%{?_pvtz_opt > 0}
%define PVTZ _PVTZ
%endif
%if 0%{?_ipv6_opt > 0}
%define IPV6 _IPV6
%endif

%define patch_version 1
%define adns_version %{major_version}.%{minor_version}.%{patch_version}%{?nic}%{?PVTZ}%{?IPV6}

Name: adns-core_IPV6
License: Alibaba
Vendor: Alibaba
Summary: Alibaba authority DNS server
Group: OPS
Version:2.34.0
Release: %(echo $RELEASE)%{?dist}
URL: http://www.taobao.com
BuildArch: x86_64
SOURCE0: %{name}.tar.gz


%define _prefix /home/adns

%description
Alibaba authority DNS server

%prep
%setup -q -c

%build
# build dpdk
pushd ./dpdk
rte_sdk=`pwd`
kernel_version=`cat /etc/redhat-release|cut -d " " -f 7|cut -d "." -f 1`
[[ $kernel_version == 7 ]] && kernel="3.10.0-327.ali2012.alios7.x86_64"
[[ $kernel_version == 6 ]] && kernel="2.6.32-220.23.2.ali878.el6.x86_64"
RTE_KERNELDIR=${DEP_VAR}usr/src/kernels/$kernel/ make config T=x86_64-native-linuxapp-gcc
RTE_KERNELDIR=${DEP_VAR}usr/src/kernels/$kernel/ make install T=x86_64-native-linuxapp-gcc DESTDIR=$rte_sdk

popd

# build adns
unset RTE_SDK
unset RTE_TARGET
make 40G=%{_40g_opt} PVT_ZONE=%{_pvtz_opt} IPV6=%{_ipv6_opt}
make install PACKAGING=1 40G=%{_40g_opt} PVT_ZONE=%{_pvtz_opt} IPV6=%{_ipv6_opt}
cp ${DEP_VAR}/../../../extern/ndns -r extern/
cp rpm/build.sh.andns extern/ndns/
cd extern/ndns
sh build.sh.andns
cp ./nginx-1.16.0/objs/nginx ../../target/bin/
cd ../../

%install
# unsolved here we must use RPM_BUILD_ROOT
rm -rf $RPM_BUILD_ROOT
mkdir -p ${RPM_BUILD_ROOT}%{_prefix}
mkdir -p ${RPM_BUILD_ROOT}%{_prefix}/etc
mkdir -p ${RPM_BUILD_ROOT}%{_prefix}/kmod
mkdir -p ${RPM_BUILD_ROOT}%{_prefix}/bin
mkdir -p ${RPM_BUILD_ROOT}%{_prefix}/scripts
mkdir -p ${RPM_BUILD_ROOT}%{_prefix}/zones
mkdir -p ${RPM_BUILD_ROOT}%{_prefix}/var/log
mkdir -p ${RPM_BUILD_ROOT}%{_prefix}/dump
mkdir -p ${RPM_BUILD_ROOT}%{_prefix}/scm/corp
mkdir -p ${RPM_BUILD_ROOT}%{_prefix}/scm/hiadns-a-190g-ndns
mkdir -p ${RPM_BUILD_ROOT}%{_prefix}/scm/hiadns-v-190g-ndns
mkdir -p ${RPM_BUILD_ROOT}%{_prefix}/scm/hiadns-v-95g-ndns


mkdir -p %{buildroot}/usr/local/adns_tsar/
mkdir -p %{buildroot}/usr/local/adns_tsar/modules/
mkdir -p %{buildroot}/usr/local/adns_tsar/conf/
mkdir -p %{buildroot}/usr/local/adns_tsar/devel/
mkdir -p %{buildroot}/usr/local/man/man8/
mkdir -p %{buildroot}/etc/logrotate.d/
mkdir -p %{buildroot}/etc/adns_tsar/conf.d/
mkdir -p %{buildroot}/etc/adns_tsar/
mkdir -p %{buildroot}/etc/cron.d/
mkdir -p %{buildroot}/usr/bin

install -m755 target/bin/* %{buildroot}%{_prefix}/bin
install -m644 target/etc/* %{buildroot}%{_prefix}/etc
install -m755 target/kmod/* %{buildroot}%{_prefix}/kmod
install -m755 target/scripts/* %{buildroot}%{_prefix}/scripts
install -m666 target/var/log/* %{buildroot}%{_prefix}/var/log
install -p -D -m 0644 scm/hiadns-a-190g-ndns/* %{buildroot}%{_prefix}/scm/hiadns-a-190g-ndns
install -p -D -m 0644 scm/hiadns-v-190g-ndns/* %{buildroot}%{_prefix}/scm/hiadns-v-190g-ndns
install -p -D -m 0644 scm/hiadns-v-95g-ndns/* %{buildroot}%{_prefix}/scm/hiadns-v-95g-ndns
install -p -D -m 0644 scm/corp/* %{buildroot}%{_prefix}/scm/corp
install -p -D -m 0755 scm/*.sh %{buildroot}%{_prefix}/scm


install -p -D -m 0755 adns_tsar/src/adns_tsar  %{buildroot}/usr/bin/adns_tsar
install -p -D -m 0644 adns_tsar/conf/adns_tsar.conf %{buildroot}/etc/adns_tsar/adns_tsar.conf
install -p -D -m 0644 adns_tsar/modules/*.so %{buildroot}/usr/local/adns_tsar/modules/
install -p -D -m 0644 adns_tsar/adns_modules/*.so %{buildroot}/usr/local/adns_tsar/modules/
install -p -D -m 0644 adns_tsar/adns_modules/*.conf %{buildroot}/etc/adns_tsar/conf.d/
install -p -D -m 0644 adns_tsar/conf/adns_tsar.cron %{buildroot}/etc/cron.d/adns_tsar
install -p -D -m 0644 adns_tsar/conf/adns_tsar.logrotate %{buildroot}/etc/logrotate.d/adns_tsar
install -p -D -m 0644 adns_tsar/conf/adns_tsar.8 %{buildroot}/usr/local/man/man8/adns_tsar.8

install -p -D -m 0755 adns_tsar/devel/adns_tsardevel %{buildroot}/usr/bin/adns_tsardevel
install -p -D -m 0644 adns_tsar/devel/mod_test.c %{buildroot}/usr/local/adns_tsar/devel/mod_test.c
install -p -D -m 0644 adns_tsar/devel/mod_test.conf %{buildroot}/usr/local/adns_tsar/devel/mod_test.conf
install -p -D -m 0644 adns_tsar/devel/Makefile.test %{buildroot}/usr/local/adns_tsar/devel/Makefile.test
install -p -D -m 0644 adns_tsar/devel/adns_tsar.h %{buildroot}/usr/local/adns_tsar/devel/adns_tsar.h

find %{buildroot} -name "*.pyc" -exec rm -rf "{}" \;
find %{buildroot} -name "*.pyo" -exec rm -rf "{}" \;

%clean
rm -rf ${RPM_BUILD_DIR}/%{name}
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf ${RPM_BUILD_ROOT} && rm -rf ${RPM_BUILD_ROOT}/../dpdk

%files
%defattr(-,root,root,-)
%{_prefix}/kmod/igb_uio.ko
%{_prefix}/kmod/rte_kni.ko
%{_prefix}/bin/nginx
%{_prefix}/bin/libadns.a
%{_prefix}/bin/libcrypto.a
%{_prefix}/bin/libssl.a
%{_prefix}/bin/adns_adm
%{_prefix}/bin/adns
%{_prefix}/scripts/id_name.py*
%{_prefix}/scripts/mk_header.py*
%{_prefix}/scripts/dpdk_nic_bind.py*
%{_prefix}/scripts/dpdk-pmdinfo.py*
%{_prefix}/scripts/pre_conv.py*
%{_prefix}/scripts/deploy.sh
%{_prefix}/scripts/check_init.sh
%{_prefix}/scripts/check_config.sh
%{_prefix}/scripts/cpu_layout.py*
%{_prefix}/scripts/dpdk-setup.sh
%{_prefix}/zones
%{_prefix}/var/log
%{_prefix}/dump
%{_prefix}/scm/*
%{_prefix}/scm/hiadns-a-190g-ndns/*
%{_prefix}/scm/hiadns-v-190g-ndns/*
%{_prefix}/scm/hiadns-v-95g-ndns/*
%{_prefix}/scm/corp/*


/usr/local/adns_tsar/modules/*.so
/etc/adns_tsar/conf.d/*.conf

%attr(755,root,root) /usr/bin/adns_tsar
%config(noreplace) /etc/adns_tsar/adns_tsar.conf
%attr(644,root,root) /etc/cron.d/adns_tsar
%attr(644,root,root) /etc/logrotate.d/adns_tsar
%attr(644,root,root) /usr/local/man/man8/adns_tsar.8

/usr/local/adns_tsar/devel/adns_tsar.h
/usr/local/adns_tsar/devel/Makefile.test
/usr/local/adns_tsar/devel/mod_test.c
/usr/local/adns_tsar/devel/mod_test.conf
%attr(755,root,root) /usr/bin/adns_tsardevel

%config %{_prefix}/etc/ip_range.map
%config %{_prefix}/etc/view_name_id.map
%config %{_prefix}/etc/adns.conf
%config %{_prefix}/etc/adns_logrotate.conf
%config %{_prefix}/etc/adns_logrotate_3T.conf

%changelog

