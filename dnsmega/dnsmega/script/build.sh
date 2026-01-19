#!/bin/sh
RPMBUILD='/usr/bin/rpmbuild'
RPM_BUILD_DIR=`rpm --eval '%_builddir'`
RPM_BIN_DIR=`rpm --eval '%_rpmdir'`
RPM_SOURCE_DIR=`rpm --eval '%_sourcedir'`
RPM_SPEC_DIR=`rpm --eval '%_specdir'`
KERNEL_VER=ali878.el6
MOD_NAME=dnsmega
VERSION=1.3.14
RELEASE=1
BUILD_DIR="$MOD_NAME"-build

SRPM_NAME=$MOD_NAME-$VERSION-$RELEASE
RPM_NAME=$MOD_NAME-$VERSION-$RELEASE
SRC_NAME=$MOD_NAME-$VERSION


#RPM Process
pushd ..;export DNS_TRUNK=`pwd`; popd
pushd ..;make clean;popd
mkdir -p $BUILD_DIR/script/
cp -r ../src $BUILD_DIR
cp -r ../mk $BUILD_DIR
cp -r ../script/dnsmega $BUILD_DIR/script/
cp -r ../script/dnsmega.modules $BUILD_DIR/script/
cp ../Makefile $BUILD_DIR
pushd $BUILD_DIR
tar zcvf ../$SRC_NAME.tar.gz ./*
popd
rm -rf $BUILD_DIR

mv $SRC_NAME.tar.gz $RPM_SOURCE_DIR/
sed -e "s/\$RELEASE/$RELEASE/g" < ../misc/rpm/$MOD_NAME.spec > $RPM_SPEC_DIR/$MOD_NAME.spec
$RPMBUILD -ba $RPM_SPEC_DIR/$MOD_NAME.spec

echo "-------------------- DNS MEGA RPMS ---------------------"
#
ls $RPM_BIN_DIR
cp $RPM_BIN_DIR/x86_64/"$RPM_NAME"*.x86_64.rpm ./
