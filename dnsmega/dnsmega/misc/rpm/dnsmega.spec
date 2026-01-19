%define name dnsmega
%define version 1.3.14
%define kernel 2.6.32-220.23.2.ali878.el6.x86_64

Summary: dnsmega
Name: %{name}
Version: %{version}
Release: %(echo $RELEASE)%{?dist}
License: GPL
Group: System Environment/Kernel
Vendor: mogu.lwp@alibaba-inc.com;songyi.sy@alibaba-inc.com;mayong.my@alibaba-inc.com
Packager: mogu.lwp@alibaba-inc.com
BuildArch: x86_64
Source: %{name}-%{version}.tar.gz
Provides: %{name}-%{version}-%{release}
Buildroot : %{_tmppath}/%{name}-root
URL: https://aone.alibaba-inc.com/project/401991

#requires: kernel-x86_64 = 2.6.32-220.23.2.ali878.el6

%description
DNS Mega, come from DNS Megalith.
High performance DNS cache for BIND, improve BIND qps.
A Linux kernel module.

%prep
%setup -c -n %{name}-%{version}

%build
pwd
export DNS_TRUNK=`pwd`
echo $BUILD_DIR
make -C src/knl
make -C src/util

%install
MOD_NAME=dnsmega
KERNEL_RELEASE=%{kernel_version}.x86_64
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/bin/
mkdir -p $RPM_BUILD_ROOT/lib/modules/${KERNEL_RELEASE}/dns/
mkdir -p $RPM_BUILD_ROOT/etc/sysconfig/modules/
cp src/knl/$MOD_NAME.ko $RPM_BUILD_ROOT/lib/modules/${KERNEL_RELEASE}/dns/
cp src/util/dnsmega_adm $RPM_BUILD_ROOT/usr/bin/
cp script/dnsmega $RPM_BUILD_ROOT/usr/bin/
cp script/dnsmega.modules $RPM_BUILD_ROOT/etc/sysconfig/modules/
chmod +x $RPM_BUILD_ROOT/usr/bin/dnsmega_adm

%files
%defattr(-,root,root,-)
/usr/bin/*
/lib/modules
/etc/sysconfig/modules/

%post
MOD_NAME=dnsmega
if [ -e "/boot/System.map-%{kernel_version}.x86_64" ]; then
/sbin/depmod -aeF "/boot/System.map-%{kernel_version}.x86_64" "%{kernel_versionernel_version}.x86_64" > /dev/null || :
fi
echo "Install $MOD_NAME module finished."

%preun
MOD_NAME=dnsmega
echo "Ready to unstall $MOD_NAME module."

%postun
MOD_NAME=dnsmega
if [ -e "/boot/System.map-%{kernel_version}.x86_64" ]; then
/sbin/depmod -aeF "/boot/System.map-%{kernel_version}.x86_64" "%{kernel_version}.x86_644" > /dev/null || :
fi
echo "Uninstall $MOD_NAME module finished."


%clean
rm -rf $RPM_BUILD_DIR/%{name}
rm -rf $RPM_BUILD_ROOT

%changelog
* Thu Mar 8 2018 -Long Weiping<mogu.lwp@alibaba-inc.com> -1.3.14-1
- 新增对于 NXDOMAIN 和 SERVFAIL 在缓存更新的开关
* Mon Feb 22 2018 -Long Weiping<mogu.lwp@alibaba-inc.com> -1.3.13-1
- 新增不更新递归失败的域名特性
- 修复 rmmod 内存回收不完整的 bug
* Wed Dec 20 2017 -Long Weiping<mogu.lwp@alibaba-inc.com> -1.3.12-1
- 域名支持所有字符
* Mon Nov 27 2017 -Long Weiping<mogu.lwp@alibaba-inc.com> -1.3.11-1
- 修复了 rmmod 时，g_node_cache 结构 destroy 失败引起的 crash
- 优化了部分日志
* Mon Nov 13 2017 -Long Weiping<mogu.lwp@alibaba-inc.com> -1.3.10-1
- 修复了哈希 waitlist 可能溢出的 bug
- 修复了 expand_copy 后，协议栈执行 NF_DROP 流程中 skb 可能指针失效的 bug
* Thu Aug 31 2017 -Long Weiping<mogu.lwp@alibaba-inc.com> -1.3.9-1
- 修复当缓存更新时触发更新的 DNS 请求会应答两个重复包的问题
* Thu Aug 17 2017 -Long Weiping<mogu.lwp@alibaba-inc.com> -1.3.8-1
- 优化计数器，更新缓存不再被限速
* Tue Jul 18 2017 -Long Weiping<mogu.lwp@alibaba-inc.com> -1.3.7-1
- 修复由于 Local_out 捕获了 Mega 自身的回包，引起的自更新问题
* Wed May 17 2017 -Long Weiping<mogu.lwp@alibaba-inc.com> -1.3.6-1
- 修复复杂原因引起 vpc DNS 服务器 crash 问题
* Mon Apr 24 2017 -Long Weiping<mogu.lwp@liababa-inc.com> -1.3.5-1
- 修复由于分配空间失败可能引起的 crash 问题
* Tue Apr 11 2017 -Long Weiping<mogu.lwp@alibaba-inc.com> -1.3.3-1
- 修复 LOCAL_IN HOOK 点的优先级高于 iptables 的问题
* Wed Mar 22 2017 -Long Weiping<mogu.lwp@alibaba-inc.com> -1.3.2-1
- 修复由 dns 解析代码引起的内核 crash 问题
* Wed Jan 1 2017 -Long Weiping<mogu.lwp@alibaba-inc.com> -1.3.1-1
- 新增 qps 限速日志打印特性
* Sat Dec 12 2016 -Long Weiping<mogu.lwp@alibaba-inc.com> -1.3.0-1
- 新增 RR 轮训特性
* Tue Nov 8 2016 -Long Weiping<mogu.lwp@alibaba-inc.com> -1.2.2-1
- 修复 timer 操作锁缺失问题
* Sat Oct 20 2016 -Long Weiping<mogu.lwp@alibaba-inc.com> -1.2.1-1
- 支持 VPC 模块
* Mon Sep 10 2016 -Long Weiping<mogu.lwp@alibaba-inc.com> -1.2.0-1
- 单 ip 限速，修复用户态工具 dnsmega_adm
* Wed Aug 10 2016 -Long Weiping<mogu.lwp@alibaba-inc.com> -1.1.0-1
- 首次 release 生成内核模块和管理工具，分别在 /usr/bin/dnsmega_adm , /lib/modules/2.6.32-220.23.2.ali878.el6/dns/dnsmega.ko
