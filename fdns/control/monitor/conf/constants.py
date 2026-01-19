#coding=utf-8
__author__ = 'weiguo.cwg'

from multiprocessing import Queue

PDNS_SYNC_STAUS_INIT = 0
PDNS_SYNC_STAUS_DOING = 1
PDNS_SYNC_STAUS_ERROR = 99
PDNS_SYNC_STAUS_TIMEOUT = 100
PDNS_SYNC_STAUS_FINISHED = 999999



LOG_HANDLE_NAME = "pdns-monitor"


API_ACTION_DEL_RR = "delRr"


SERVER_TYPE_FWD = "forwarder"
SERVER_TYPE_REDIS = "redis"
SERVER_TYPE_CDN = "cdn"

MAX_RETRY_COUNT = 3

AGENT_FUNC_DEL_DOMAIN = "delDomain"
AGENT_FUNC_MONITOR_SERVER_STATUS = "monitorServ"

QUEUE_CMD_ADD = "add_task"
QUEUE_CMD_RET = "agent_ret"

MAX_QUEUE_SIZE = 100000
result_queue = Queue(maxsize=MAX_QUEUE_SIZE)
task_queue = Queue(maxsize=MAX_QUEUE_SIZE)
