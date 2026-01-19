#!/bin/sh
LOG=@base/crontab/download_top.log
TOP=@base/crontab/top
URL=http://110.75.103.78/top

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
	cd @base/crontab/
	rm -f $TOP
	rm -f $TOP.bak
	
	wget $URL
	ck "wget $URL"	

	cp $TOP $TOP.bak
	sed -i '1d' $TOP
	sed -i '1i\-----topNdataok-----'  $TOP
	mv $TOP @base/.topn_active
	ck "New topn date come"


}

run
