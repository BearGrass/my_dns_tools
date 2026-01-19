Summary: asmega
Name: asmega
Version: 1.0.0
Release: %(echo $RELEASE)%{?dist}
License: GPL
Group: System Environment/Kernel
Vendor: mogu.lwp@alibaba-inc.com;mayong.my@alibaba-inc.com
Packager: mogu.lwp@alibaba-inc.com
BuildArch: x86_64
Source: %{name}-%{version}.tar.gz
Provides: %{name}-%{version}-%{release}
URL: https://aone.alibaba-inc.com/task/17737019

%description
A Linux kernel module for vxlan net enviroment,get tunnel id from vxlan and put edns0 to dns packages.

%prep
%setup -c -n %{name}-%{version}

%build
export DNS_TRUNK=`pwd`
pwd
make -C src
cd -

%install
echo $RPM_BUILD_ROOT
rm -rf $RPM_BUILD_ROOT
MOD_NAME=asmega
#rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/bin/
mkdir -p $RPM_BUILD_ROOT/etc/sysconfig/modules/
mkdir -p $RPM_BUILD_ROOT/var/dns/asmega/
mkdir -p $RPM_BUILD_ROOT/var/dns/asmega/lib/
cp -r target/* $RPM_BUILD_ROOT/var/dns/asmega/
cp src/asmega_adm/asmega_adm $RPM_BUILD_ROOT/var/dns/asmega/bin/
cp src/asmega_adm/libasmega_adm.so $RPM_BUILD_ROOT/var/dns/asmega/lib/
cp target/scripts/asmega.modules $RPM_BUILD_ROOT/etc/sysconfig/modules/

%files
%defattr(-,root,root,-)
/var/dns/asmega/*
/etc/sysconfig/modules/


%post
MOD_NAME=asmega
if [ -e "/boot/System.map-%{kernel_version}.x86_64" ]; then
/sbin/depmod -aeF "/boot/System.map-%{kernel_version}.x86_64" "%{kernel_version}.x86_64" > /dev/null || :
fi
echo "Install $MOD_NAME module finished."

%preun
MOD_NAME=asmega
echo "Ready to unstall $MOD_NAME module."

%postun
MOD_NAME=asmega
if [ -e "/boot/System.map-%{kernel_version}.x86_64" ]; then
/sbin/depmod -aeF "/boot/System.map-%{kernel_version}.x86_64" "%{kernel_version}.x86_64" > /dev/null || :
fi
echo "Uninstall $MOD_NAME module finished."


%clean
#rm -rf $RPM_BUILD_DIR/%{name}
#rm -rf $RPM_BUILD_ROOT

%changelog
* Mon Jan 28 2019 -Long Weiping<mogu.lwp@alibaba-inc.com> -1.0
- 首次 release 生成内核模块和管理工具
