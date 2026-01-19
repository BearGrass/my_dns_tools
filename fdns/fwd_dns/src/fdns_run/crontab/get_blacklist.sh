#!/bin/sh
LOG=/work/dpdk_fwrd/crontab/download_blacklist.log
FILE=/work/dpdk_fwrd/crontab/blacklist
URL=http://100.67.125.6/blacklist


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
}

function run(){
	cd /work/dpdk_fwrd/crontab/
	rm -f $FILE
	rm -f $FILE.bak
	while [ true ] ; do
		wget -c -T 1 -w 1 $URL
		ck "Wget $URL"
		cat $FILE >> ${LOG} 2>&1
		cp $FILE $FILE.bak
			
		sed -i '1d' $FILE
		line=`cat $FILE|wc -l`
		if [ $line -eq 0 ] ; then
			echo "-----blacklistNdataok-----" >$FILE
		else
			sed -i '1i\-----blacklistNdataok-----'  $FILE
		fi
		mv $FILE /work/dpdk_fwrd/.blacklist_active
		ck "New blacklist date come"
		sleep 1
	done
}

run
