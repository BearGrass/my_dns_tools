
%define major_version 1
%define minor_version 0
%define patch_version 1
%define adns_version %{major_version}.%{minor_version}.%{patch_version}
%define adns_release 1


Name: adns_tsar
License: Alibaba
Vendor: Alibaba
Summary: Alibaba authority DNS server
Group: OPS
Version: %{adns_version}
Release: %{adns_release}%{?dist}
URL: http://www.taobao.com
BuildArch: x86_64
Distribution: RHEL6U2
SOURCE0: %{name}.tar.gz

BuildRequires: expect
BuildRequires: kernel = 2.6.32-220.23.2.ali878.el6
BuildRequires: kernel-devel = 2.6.32-220.23.2.ali878.el6
BuildRequires: popt-devel
Requires: kernel = 2.6.32-220.23.2.ali878.el6

%description
adns_tsar is Taobao monitor tool for collect system activity status, and report it.
It have a plugin system that is easy for collect plugin development. and may
setup different output target such as local logfile and remote nagios host.

%package devel
Summary: Taobao Tsar Devel
Group: Taobao/Common
%description devel
devel package include adns_tsar header files and module template for the development


%prep
%setup -q -c

%build
make clean;make

%install
mkdir -p %{buildroot}/usr/local/adns_tsar/
mkdir -p %{buildroot}/usr/local/adns_tsar/modules/
mkdir -p %{buildroot}/usr/local/adns_tsar/conf/
mkdir -p %{buildroot}/usr/local/adns_tsar/devel/
mkdir -p %{buildroot}/usr/local/man/man8/
mkdir -p %{buildroot}/etc/logrotate.d/
mkdir -p %{buildroot}/etc/adns_tsar/conf.d/
mkdir -p %{buildroot}/etc/cron.d/
mkdir -p %{buildroot}/usr/bin

install -p -D -m 0755 src/adns_tsar  %{buildroot}/usr/bin/adns_tsar
install -p -D -m 0644 conf/adns_tsar.conf %{buildroot}/etc/adns_tsar/adns_tsar.conf
install -p -D -m 0644 modules/*.so %{buildroot}/usr/local/adns_tsar/modules/
install -p -D -m 0644 adns_modules/*.so %{buildroot}/usr/local/adns_tsar/modules/
install -p -D -m 0644 adns_modules/*.conf %{buildroot}/etc/adns_tsar/conf.d/
install -p -D -m 0644 conf/adns_tsar.cron %{buildroot}/etc/cron.d/adns_tsar
install -p -D -m 0644 conf/adns_tsar.logrotate %{buildroot}/etc/logrotate.d/adns_tsar
install -p -D -m 0644 conf/adns_tsar.8 %{buildroot}/usr/local/man/man8/adns_tsar.8

install -p -D -m 0755 devel/adns_tsardevel %{buildroot}/usr/bin/adns_tsardevel
install -p -D -m 0644 devel/mod_test.c %{buildroot}/usr/local/adns_tsar/devel/mod_test.c
install -p -D -m 0644 devel/mod_test.conf %{buildroot}/usr/local/adns_tsar/devel/mod_test.conf
install -p -D -m 0644 devel/Makefile.test %{buildroot}/usr/local/adns_tsar/devel/Makefile.test
install -p -D -m 0644 devel/adns_tsar.h %{buildroot}/usr/local/adns_tsar/devel/adns_tsar.h



find %{buildroot} -name '*.pyc' -delete
find %{buildroot} -name '*.pyo' -delete

%clean
rm -rf ${RPM_BUILD_DIR}/%{name}
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf ${RPM_BUILD_ROOT}

%files
%defattr(-,root,root,-)
/usr/local/adns_tsar/modules/*.so
/etc/adns_tsar/conf.d/*.conf
%attr(755,root,root) %dir /usr/bin/adns_tsar
%config(noreplace) /etc/adns_tsar/adns_tsar.conf
%attr(644,root,root) %dir /etc/cron.d/adns_tsar
%attr(644,root,root) %dir /etc/logrotate.d/adns_tsar
%attr(644,root,root) %dir /usr/local/man/man8/adns_tsar.8

/usr/local/adns_tsar/devel/adns_tsar.h
/usr/local/adns_tsar/devel/Makefile.test
/usr/local/adns_tsar/devel/mod_test.c
/usr/local/adns_tsar/devel/mod_test.conf
%attr(755,root,root) %dir /usr/bin/adns_tsardevel

%changelog

