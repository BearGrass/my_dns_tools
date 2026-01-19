#!/bin/sh
if [ -z "$LOG_BASE" ]  ; then
	echo "LOG_BASE not set"
	exit 1;
fi

cd $LOG_BASE;

pkill -9 -f supervise

if [ "$1" == "clean" ] ; then
	dirs=("query_log server_log answer_log attack_log secure_log")
	for i in ${dirs[@]} ; do
		rm -rf $LOG_BASE/$i/*		
		mkdir -p $LOG_BASE/$i
	done
fi

[ ! -d $LOG_BASE/pipe ] && mkdir $LOG_BASE/pipe

logs=("fwd_answer fwd_query fwd_server fwd_attack fwd_secure")
for log in ${logs[@]} ; do
	#remove old file,cause it may not pipe file
	pipe_file="$LOG_BASE/pipe/$log.log"
	rm -f "$pipe_file"
	mkfifo --mode=666 "$pipe_file";
	[ ! -p "$pipe_file" ] && (echo "$pipe_file create fail" ;exit 1);
	$LOG_BASE/bin/supervise $LOG_BASE/bin/"$log"_supervise &
done

