#!/bin/sh

# prepare deps_create configure file
echo "[deps]" > adns-core_MLX.deps
kernel_version=`cat /etc/redhat-release|cut -d " " -f 7|cut -d "." -f 1`
[[ $kernel_version == 7 ]] && echo -e "\texpect-5.45-14.1.alios7.x86_64.rpm\n\tkernel-devel-3.10.0-327.ali2012.alios7.x86_64.rpm=stable\n\tkernel-headers-3.10.0-327.ali2012.alios7.x86_64.rpm=stable" >> adns-core_MLX.deps
[[ $kernel_version == 6 ]] && echo -e "\tkernel-devel-2.6.32-220.23.2.ali878.el6.x86_64.rpm=current\n\tkernel-headers-2.6.32-220.23.2.ali878.el6.x86_64.rpm=current" >> adns-core_MLX.deps
dep_create adns-core_MLX

# current dir is git_repo/rpm
ABS_PATH=`pwd`
TOP_DIR=".rpm_create"

# overwrite %_topdir to git_repo/rpm/.rpm_create in .rpmmacros
RPM_MACROS=$HOME/.rpmmacros
if [ -e $RPM_MACROS ]; then
      mv -f $RPM_MACROS $RPM_MACROS.bak
  fi
  echo "%_topdir $ABS_PATH/$TOP_DIR" > $RPM_MACROS

# cd in the git_repo
cd $1

# same as old adns rpm packaging method, make sources and make rpm [option]
git submodule init
git submodule update
cd extern/ndns
git pull origin master
cd ../../
make sources

rm -rf /var/tmp/adns
rm -rf /var/tmp/dpdk
rm -rf /var/tmp/adns_tsar

rm -rf $ABS_PATH/$TOP_DIR
mkdir -p $ABS_PATH/$TOP_DIR/SOURCES
cp adns-core.tar.gz $ABS_PATH/$TOP_DIR/SOURCES/adns-core_MLX.tar.gz
# set rpm buildroot
rpmbuild -bb rpm/adns-core_MLX.spec --buildroot=$ABS_PATH/$TOP_DIR/BUILDROOT --define '_mlx_opt 1' --define '_ipv6_opt 0' --define '_pvtz_opt 0'
