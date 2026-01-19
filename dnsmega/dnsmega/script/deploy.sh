#!/bin/bash

HOST="dnstest05.tbc"
#HOST="anydnsin6.et15sqa"
DIR="/home/mogu.lwp/"
MAKE="/usr/bin/make"
TAR="/bin/tar"
SCP="/usr/bin/scp"
SSH="/home/tops/bin/pgm"

echo "purging compile enviroment..."
#export DNS_TRUNK="/home/mogu.lwp/git/ais/projects/dns/dnsmega"
pushd ..;$MAKE clean;popd

pushd ../..;rm -f dnsmega.tar.gz;$TAR -zcf dnsmega.tar.gz dnsmega;echo "deploy Mega to $HOST";$SCP dnsmega.tar.gz $HOST:$DIR;popd

$SSH $HOST "sudo pkill python;sudo pkill named"
#$SCP network_irq.sh $HOST:$DIR
#$SSH $HOST "sudo /bin/bash network_irq.sh -s"
#$SSH $HOST "sudo /etc/init.d/iptables stop"
$SSH $HOST "sudo /etc/init.d/named restart"
$SSH $HOST "sudo rm ${DIR}dnsmega -rf"
$SSH $HOST "/bin/tar -zxf ${DIR}dnsmega.tar.gz;cd dnsmega;make;"
$SSH $HOST "sudo rmmod dnsmega"
$SSH $HOST "sudo insmod ${DIR}dnsmega/src/knl/dnsmega.ko"
