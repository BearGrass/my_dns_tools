#e.g
#require: RTE_SDK,RTE_TARGET env has set,dpdk src has put at $RTE_SDK directory
#

#mkdir ~/tmp/
#cd ~/tmp/
#git clone git@gitlab.alibaba-inc.com:dns/fdns.git
#cd fdns
#git checkout remotes/origin/fdns_2.0.1_beta -b tfdns2
#cd ~/tmp/fdns/fwd_dns/src/
#sh build_rpm.sh ~/tmp/fdns 

if [ "x$RTE_SDK" == "x" ] || [ "X$RTE_TARGET" == "X" ] ;then
	echo "Need dpdk env has set"
	exit 1
fi

if [ "x$1" == "x" ] ; then
        echo "Need fdns root directory"
        exit 1
fi


echo "%_topdir $HOME/rpmbuild/" >~/.rpmmacros
mkdir $HOME/rpmbuild/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS} >/dev/null 2>&1
make clean
cd $1
tar jcvf $HOME/rpmbuild/SOURCES/fdns.tar.bz2 ./* --exclude=*/fwd_dns_bin  --exclude=*.git --exclude=*.tar.bz2
cd -
rpmbuild -ba ../misc/fdns.spec
