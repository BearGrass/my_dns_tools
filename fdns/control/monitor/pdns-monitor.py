#coding=utf-8
__author__ = 'weiguo.cwg'

import logging
import traceback

from apscheduler.scheduler import Scheduler

from conf import settings,constants
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                    datefmt='%a, %d %b %Y %H:%M:%S',
                    filename="%s/%s.log" % (settings.LOGGING_PATH, constants.LOG_HANDLE_NAME),
                    filemode='a')
log = logging.getLogger(constants.LOG_HANDLE_NAME)


from util import mtxscheduler
import db_manager
import ap_task
import ap_task_deal


sched = mtxscheduler.MutexScheduler(daemonic=False)
sched_check = Scheduler(daemonic=False)


def lock_sync_pdns():
    return db_manager.lock_base("monitor_pdns_task.lock")

def hb_sync_pdns(ip, now, **attrs):
    db_manager.hb_base(ip, now, "monitor_pdns_task.lock", **attrs)


# 定时从DB获取需要同步的任务
@sched.mutex(lock=lock_sync_pdns, heartbeat=hb_sync_pdns, lock_else=db_manager.le)
@sched.cron_schedule(second='0-59/2', minute='*')
def repair_job(**attr):
    """
    now sync pdns domain
    """
    log.info('now sync pdns domain')
    ap_task.sync_with_pdns()


def lock_pdns_monitor():
    return db_manager.lock_base("monitor_pdns_server.lock")

def hb_pdns_monitor(ip, now, **attrs):
    db_manager.hb_base(ip, now, "monitor_pdns_server.lock", **attrs)

# 定时从DB获取需要同步的任务
@sched.mutex(lock=lock_pdns_monitor, heartbeat=hb_pdns_monitor, lock_else=db_manager.le)
@sched.cron_schedule(second='0-59/15', minute='*')
def pdns_monitor_job(**attr):
    """
    now monitor pdns process status/version
    """
    log.info('now monitor pdns status version')
    ap_task.monitor_pdns()

sched.start()
sched_check.start()


if __name__ == "__main__":
    # 启动多进程，从队列中获取任务, 任务进程会堵塞
    ap_task_deal.start_queue_task_process()
    # parse_queue_task(0, g_queue_list[0])
