#!/bin/bash
HOST="0.0.0.0"
PORT=8000

PROJECT_PATH=/home/work/pdns-monitor
#PROJECT_PATH=/home/weiguo.cwg/fdns/control/monitor
export PATH=/home/tops/bin:$PATH
LOGGING=$PROJECT_PATH/logs
if [ ! -d $LOGGING ]
then
    mkdir -p $LOGGING
fi
action=$1

function pdns_monitor_status(){
  ps aux | grep "pdns-admin.py" |grep -v grep >& /dev/null
  status=$?
  if [ $status -eq 0 ]
  then
      echo -e "pdns-admin status [\e[1;32mON\e[0m]"
  else
      echo -e "pdns-admin status [\e[1;31mOFF\e[0m]"
  fi

}


function start_pdns_monitor(){
    nohup /bin/env python $PROJECT_PATH/pdns-admin.py>& $LOGGING/pdns-admin-nohup.log &
    sleep 1
    pdns_monitor_status
}

function pdns_monitor_stop(){
    ps aux |grep "pdns-admin.py" |grep -v grep | tr -s " "|cut -d" " -f 2 |xargs -I {}  kill {}
    sleep 1
    pdns_monitor_status
}

function start(){
    start_pdns_monitor
}

function stop(){
    pdns_monitor_stop
}

function status(){
    pdns_monitor_status
}

function restart(){
    stop
    start
}
case $action in
    start)
        start
        ;;
    stop)
        stop
        ;;
    status)
        status
        ;;
    restart)
        stop
        start
        ;;
    *)
     echo "USAGE:$0 {start|stop|restart|status}"
     exit 2
esac
