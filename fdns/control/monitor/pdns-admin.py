#coding=utf-8
__author__ = 'weiguo.cwg'

import logging
import time
from multiprocessing import Process
import traceback
import os
import signal

from flask import Flask, request
from flask.ext import restful
from flask.ext.restful import Resource, reqparse, marshal, fields


from conf import settings,constants
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                    datefmt='%a, %d %b %Y %H:%M:%S',
                    filename="%s/%s.log" % (settings.LOGGING_PATH, constants.LOG_HANDLE_NAME),
                    filemode='a')
log = logging.getLogger(constants.LOG_HANDLE_NAME)


from util import WSGICopyBody
import ap_task

app = Flask(__name__)
app.wsgi_app = WSGICopyBody.WSGICopyBody(app.wsgi_app)
api = restful.Api(app)

RESPONSE_OK = {
    "code": "000",
    "success": True,
    "message": "ok"
}


g_process_pid = []

def process_pdns_server_check():
    """
    create dns server status check
    """
    try :
        log.info("start process_pdns_server_check at::%s" % time.ctime())
        pid = Process(target=ap_task.monitor_pdns, args=(0, constants.task_queue))
        pid.daemon = True
        pid.start()
        g_process_pid.append(pid)
    except :
        log.error("start_queue_task_process error:%s" %  traceback.format_exc())
        os._exit(-1)

def process_sync_task_get():
    """
    get sync task from db.adms_task
    """
    try:
        log.info("start process_sync_task_get at::%s" % time.ctime())
        pid = Process(target=ap_task.sync_with_pdns, args=(0, constants.result_queue, constants.task_queue))
        pid.daemon = True
        pid.start()
        g_process_pid.append(pid)
    except:
        log.error("start_queue_task_process error:%s" %  traceback.format_exc())
        os._exit(-1)

def process_sync_task_check():
    """
    处理联动跟新处理结果
    """
    try:
        log.info("start process_sync_task_check at::%s" % time.ctime())
        pid = Process(target=ap_task.sync_result_check, args=(0, constants.result_queue, constants.task_queue))
        pid.daemon = True
        pid.start()
        g_process_pid.append(pid)
    except:
        log.error("start_queue_task_process error:%s" %  traceback.format_exc())
        os._exit(-1)



def process_queue_task_deal():
        process_queue = []

        for index in range(settings.MULTIPROCESS_NUM) :
            try :
                # pid = Process(target=parse_queue_task, args=(index, ))
                pid = Process(target=ap_task.parse_queue_task, args=(index, constants.result_queue, constants.task_queue))
                log.info("start_queue_task_process index:%s" % index)
            except :
                log.error("start_queue_task_process error:%s" %  traceback.format_exc())
                os._exit(-1)
            else :
                process_queue.append(pid)

        for pid in process_queue:
            pid.start()
            g_process_pid.append(pid)



def sig_handler(sig, frame):
    try:
        for pid in g_process_pid:
            if pid.is_alive():
                pid.terminate()
        os._exit(-1)
    except Exception, ex:
        os._exit(-1)


def init_process():
    """
    create multi process for
    1) dns server status check
    2) sync tack get
    3) sync task deal;
    """
    signal.signal(signal.SIGINT, sig_handler)
    #创建pdns机器状态校验进程
    process_pdns_server_check()

    #创建联动更新任务获取进程
    process_sync_task_get()

    #创建线程池，处理队列任务
    process_queue_task_deal()

    #创建联动更新任务获取进程
    process_sync_task_check()


class SYS_CHECK(Resource):
    """
    test
    """
    def get(self):
        log.info("api enter SYS_CHECK, get")

    def post(self):
        log.info("api enter SYS_CHECK, post")


#api.add_resource(SYS_CHECK, "/sys_check")

if __name__ == '__main__':
    #log.info("Start of main process at::%s" % time.ctime())
    init_process()
    while True:
        time.sleep(10)
    #app.run(host='0.0.0.0', port=8878, debug=True)
    log.info("End of main process at::%s" % time.ctime())

