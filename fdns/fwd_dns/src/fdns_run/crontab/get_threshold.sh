#!/bin/sh
LOG=/work/dpdk_fwrd/crontab/download_threshold.log
THRESHOLD=/work/dpdk_fwrd/crontab/threshold
URL=http://100.67.125.6/threshold
COUNT=3

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
	rm -f $THRESHOLD
	rm -f $THRESHOLD.bak
	
	TRY=3;
	for((i = 0 ; i < $TRY; i ++)) ; do
		wget -c -T 10 -w 1 $URL
		if [ $? -ne 0 ] ; then
			msg "Wget $URL Fail,Retry $i";
		else
			rr=`cat $THRESHOLD |wc -l`;
			if [ $rr -le $COUNT ] ; then
				msg "threshold record <= $COUNT,not update"
				ls -l  $THRESHOLD >> ${LOG} 2>&1
				rm -f $THRESHOLD
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
	
	
	sed -i '1d' $THRESHOLD
	mv $THRESHOLD /work/dpdk_fwrd/.attack_threshold_active
	ck "New threshold date come"

}

run
