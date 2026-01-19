#!/bin/sh
LOG=/work/dpdk_fwrd/crontab/download_man_blacklist.log
TOP=/work/dpdk_fwrd/crontab/man_blacklist
URL=http://100.67.125.6/man_blacklist
COUNT=0

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
	
	TRY=10;
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
	
	
	sed -i '1d' $TOP
	sed -i '1i\-----man_blacklistNdataok-----'  $TOP
	mv $TOP /work/dpdk_fwrd/.man_blacklist_active
	ck "New man_blacklist date come"

}

run
