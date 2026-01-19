#!/bin/sh
LOG=/work/dpdk_fwrd/crontab/download_oversealist.log
TOP=/work/dpdk_fwrd/crontab/oversealist
URL=http://100.67.125.6/oversealist
COUNT=30000

function msg(){
        message=$1
        echo "`date '+%F_%T'` - ${message}" >> ${LOG} 2>&1
}

function ck(){
	if [ $? -ne 0 ] ; then
		res="Fail"
	else
		res="OK"
	fi
        message=$1
        echo "`date '+%F_%T'` - ${message} $res" >> ${LOG} 2>&1
	if [ "x$res" != "xOK" ] ; then
		exit 1;
	fi
}

function run(){
	cd /work/dpdk_fwrd/crontab/
	rm -f $TOP
	rm -f $TOP.bak
	
	TRY=100;
	for((i = 0 ; i < $TRY; i ++)) ; do
		wget -c -T 10 -w 1 $URL
		if [ $? -ne 0 ] ; then
			msg "Wget $URL Fail,Retry $i";
		else
			rr=`cat $TOP |wc -l`;
			if [ $rr -le $COUNT ] ; then
				msg "topn record <= $COUNT,not update"
				ls -l  $TOP >> ${LOG} 2>&1
				rm -f $TOP
			else
				msg "Wget $URL OK"
				break;
			fi
	
		fi
		sleep 1
	done
	
	if [ $i -eq $TRY ] ; then
		msg "Top $COUNT wget Fail , not update"
		exit 1;
	fi
	
	
	cp $TOP $TOP.bak
	#head -n $COUNT $TOP.bak> $TOP
	sed -i '1d' $TOP
	sed -i '1i\-----oversealistNdataok-----'  $TOP
	mv $TOP /work/dpdk_fwrd/.oversealist_active
	ck "New oversealist date come"

}

run
