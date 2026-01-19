#!/bin/bash
HOST="0.0.0.0"
PORT=8000

PROJECT_PATH=/home/work/pdns-agent
export PATH=/home/tops/bin:$PATH
LOGGING=$PROJECT_PATH/logs
if [ ! -d $LOGGING ]
then
    mkdir -p $LOGGING
fi
action=$1

function pdns_agent_status(){
  ps aux | grep "pdns-agent.py" |grep -v grep >& /dev/null
  status=$?
  if [ $status -eq 0 ]
  then
      echo -e "pdns-agent status [\e[1;32mON\e[0m]"
  else
      echo -e "pdns-agent status [\e[1;31mOFF\e[0m]"
  fi

}


function start_pdns_agent(){
    screen -wipe pdnsagent;
    source /home/work/pdns-agent/pyVirtuEnv/bin/activate;
    pkill -9 -f pdns-agent.py
    cd /home/work/pdns-agent;
    /home/work/pdns-agent/pyVirtuEnv/bin/uwsgi --http 0.0.0.0:9999 --wsgi-file /home/work/pdns-agent/pdns-agent.py --callable app --processes 24 --threads 2 --stats 127.0.0.1:9191 --virtualenv /home/work/pdns-agent/pyVirtuEnv --daemonize  /home/work/pdns-agent/logs/daemon.out --pidfile /home/work/pdns-agent/logs/uwsgi.pid
    pdns_agent_status
}

function pdns_agent_stop(){
    pkill -9 -f pdns-agent.py
    sleep 1
    pdns_agent_status
}

function start(){
    start_pdns_agent
}

function stop(){
    pdns_agent_stop
}

function status(){
    pdns_agent_status
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
