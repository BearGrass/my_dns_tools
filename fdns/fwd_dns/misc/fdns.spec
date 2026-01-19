%define path /work/dpdk_fwrd/
Name:	fdns	
Version:	3.6.1
Release:	1%{?dist}
Summary:	Alibaba Public DNS (forwarder dns)

Group:		Applications/Internet
License:	GPLv2
Vendor: Alibaba
Packager:   Tang Ming <ming.tang@alibaba-inc.com>  yisong <songyi.sy@alibaba-inc.com> longweiping <mogu.lwp@alibaba-inc.com>
URL:	git@gitlab.alibaba-inc.com:dns/fdns.git	
Source0:	%{name}.tar.bz2
BuildArch: x86_64
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)


%description
Alibaba public dns base on DPDK

%prep
%setup -q -c


%build
cd fwd_dns
export LDNS_TRUNK=`pwd`
cd src
make rpm


%install
rm -rf ${RPM_BUILD_ROOT}
mkdir -p ${RPM_BUILD_ROOT}%{path}
cp -a  fwd_dns/src/fdns_run/* ${RPM_BUILD_ROOT}%{path}/
cp -a  fwd_dns/src/fdns_run/.[^.]* ${RPM_BUILD_ROOT}%{path}/


%clean
rm -rf ${RPM_BUILD_ROOT}


%files
%defattr(-,root,root,-)
/*
%doc



%changelog
* Mon Jan 13 2020 -Long Weiping<mogu.lwp@alibaba-inc.com> -3.5.1
- Add features: support chaos txt hostname.fwd client.ip client.view
