#coding=utf-8
__author__ = 'weiguo.cwg'

import logging
import traceback
import json
import time
import datetime
import copy

from Queue import Empty
from multiprocessing import Queue

from conf import constants, settings
log = logging.getLogger(constants.LOG_HANDLE_NAME)


from util import utils
import db_manager
import http_manager


def monitor_pdns(queue_index, queue):
    """
    并发处理监控任务
    task = {
        "server" : {"ip":***, "port":***, "type":***, "id":***},
        "tasks" : [{
            "id":int(task[0]),
            "ip":zone,
            "port:":domain_name},
            ]
        "action":"serverMonitor"
        "retry_count" : 1
    }
    """
    conn = None
    conn = db_manager.connect_adms_db()
    while True:
        try:
            #s实时获取pdns列表
            server_list = db_manager.get_pdns_servers(conn, status=None)
            for server in server_list:
                server_task = {}
                server_task["server"]=server
                server_task["tasks"]=[server,]
                server_task["action"] = constants.AGENT_FUNC_MONITOR_SERVER_STATUS
                server_task["retry_count"]=0
                queue.put(server_task)
            log.info("queue id:%d, size:%d" % (id(queue), queue.qsize()))

        except:
            log.error("monitor_pdns except, %s" % traceback.format_exc())
        finally:
            time.sleep(30)


def task_to_json(task):
    """
     id,zone,data,api
    """
    zone = task["zone"].rstrip(".")+"."
    data = json.loads(task["data"])
    domain_name = utils.format_domain_name(zone,data.get("name", None))
    api = task["api"]
    if constants.API_ACTION_DEL_RR == api:
        action = "del"
    else:
        return None

    return {
        "id":int(task["id"]),
        "zone":zone,
        "domain_name":domain_name,
        "action":action,
        "uuid":task["uuid"],
        "s_time":task["s_time"].strftime('%Y-%m-%d %H:%M:%S')
    }

def sync_with_pdns(index, rlt_queue, task_queue):
    """
    根据adms_task中的任务，批量同步删除pdns中实现的记录
    """
    conn = db_manager.connect_adms_db()
    queue = task_queue
    large_task_flag = False
    while True:
        try:
            if True == large_task_flag:
                log.warning("large task, sleep(1)")
                time.sleep(1)
            else:
                time.sleep(0.1)
            large_task_flag = False
            #实时获取pdns列表
            server_list = db_manager.get_pdns_servers(conn, status="online")
            #server_list = db_manager.get_pdns_servers(conn, status=None)
            if 0 == len(server_list):
                log.info("no available pdns server in db")
                continue

            cdn_server = {}
            fwd_server = {}
            for server in server_list:
                if constants.SERVER_TYPE_CDN == server["type"]:
                    cdn_server[server["id"]] = server
                elif constants.SERVER_TYPE_FWD == server["type"]:
                    fwd_server[server["id"]] = server
            
            ret = db_manager.get_sync_task_lock(conn)
            if True != ret:
                log.info("no sync task lock")
                continue
            
            while True:
                if True == large_task_flag:
                    break

                # 只同步最近5 min产生的数据
                db_manager.update_sync_task_time(conn)

                s_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()-60))
                sql = "select id,zone,data,api,uuid,s_time from adms_task where pdns_sync_status=%d and api='delRr' and status='999999' and s_time>='%s' limit 100" % (constants.PDNS_SYNC_STAUS_INIT, s_time)
                log.info("sql:%s" % sql)
                tasks = conn.execute(sql)
                if 0 == len(tasks):
                    break
                if 10 <= len(tasks):
                    large_task_flag = True
                    tasks = tasks[:5]
                
                discard_num = queue.qsize() + len(tasks)*len(cdn_server) - constants.MAX_QUEUE_SIZE
                if 0 < discard_num:
                    for i in range(discard_num + 1000):
                        queue.get(timeout=1)
                    log.error("app active discard task num:%d" % (discard_num + 1000))


                for task in tasks:
                    try:
                        t = task_to_json(task)
                        if None == t:
                            log.info("cancelled task :%s" % str(task))
                            continue

                        db_manager.update_pdns_sync_status(t["id"], constants.PDNS_SYNC_STAUS_DOING, conn=conn)
                    except:
                        log.error("parse task data:%s, error:%s" % (str(task), traceback.format_exc()))
                        db_manager.update_pdns_sync_status(int(task[0]), constants.PDNS_SYNC_STAUS_ERROR, conn=conn)
                        continue

                    rlt_task = {
                            "undo_fwd":fwd_server,
                            "undo_cdn":cdn_server,
                            "err_fwd":[],
                            "err_cdn":[],
                            "time":datetime.datetime.now(),
                            "task":t,
                            "fwd_task_flag" : False
                        }
                    rlt_queue.put({"cmd":constants.QUEUE_CMD_ADD, "task_id":t["id"], "task":rlt_task})

                    # push fwd task to queue
                    for c_server in cdn_server:
                        server_task = {}
                        server_task["server"]=cdn_server[c_server]
                        server_task["tasks"]=[t]
                        server_task["action"]=constants.AGENT_FUNC_DEL_DOMAIN
                        server_task["retry_count"]=0
                        queue.put(server_task)

                    # log.info("pdns sync process start, task:%s" % str(t))

                log.info("queue id put:%d, size:%d" % (id(queue), queue.qsize()))
        except:
            log.error("sync_with_pdns error:%s" % traceback.format_exc())
        finally:
            db_manager.delete_sync_task_lock(conn)


def deal_sync_result(sync_task_dict, ret_flag, task_info):
    """
    处理sync单机操作结果
    """
    try:
        if True != sync_task_dict.has_key(task_info["tasks"][0]["id"]):
            return

        task_result = sync_task_dict[task_info["tasks"][0]["id"]]
        server = task_info["server"]

        if True != ret_flag:
            log.error("server sync domain error, server:%s, tasks:%s" % (str(server), str(task_result)))
            if constants.SERVER_TYPE_CDN == server["type"]:
                task_result["undo_cdn"].pop(server["id"])
                task_result["err_cdn"].append({"id":server["id"], "ip":server["ip"]})
            else:
                task_result["undo_fwd"].pop(server["id"])
                task_result["err_fwd"].append({"id":server["id"], "ip":server["ip"]})
        else:
            if constants.SERVER_TYPE_CDN == server["type"]:
                task_result["undo_cdn"].pop(server["id"])
            else:
                task_result["undo_fwd"].pop(server["id"])
    except:
        log.error("deal_sync_result error:%s" % traceback.format_exc())


def sync_result_check(index, rlt_queue, task_queue):
    """
    处理联动跟新处理结果
    """
    sync_task_dict = {}
    conn = db_manager.connect_adms_db()
    queue = task_queue
    task_record_info = {"err":0, "suc":0, "time":datetime.datetime.now()}
    while True:
        for i in range(1000):
            try:
                q_task = None
                q_task = rlt_queue.get(timeout=1)

                if None != q_task and type({}) == type(q_task):
                    if constants.QUEUE_CMD_ADD == q_task["cmd"]:
                        #{"cmd":constants.QUEUE_CMD_ADD, "task_id":t["id"], "task":rlt_task}
                        sync_task_dict[q_task["task_id"]] = q_task["task"]
                    elif constants.QUEUE_CMD_RET == q_task["cmd"]:
                        #{"cmd": constants.QUEUE_CMD_RET, "ret_flag":server_flag, "task": task}
                        deal_sync_result(sync_task_dict,  q_task["ret_flag"], q_task["task"])
                else:
                    break

            except Empty, e:
                time.sleep(0.01)
                break
            except:
                log.info("sync_result_check error:%s" % traceback.format_exc())

        try:
            log.info("result queue id, queue size:%d, len:%d"  % (rlt_queue.qsize(), len(sync_task_dict)))
            sync_task_temp = copy.deepcopy(sync_task_dict)

            for task_id in sync_task_temp:
                task = sync_task_dict[task_id]
                if 0 == len(task["undo_cdn"]):
                    if False == task["fwd_task_flag"]:
                        fwd_server = task["undo_fwd"]
                        # push fwd task to queue
                        for f_server in fwd_server:
                            server_task = {}
                            server_task["server"]=fwd_server[f_server]
                            server_task["tasks"]=[task["task"]]
                            server_task["action"]=constants.AGENT_FUNC_DEL_DOMAIN
                            server_task["retry_count"]=0
                            queue.put(server_task)

                            task["fwd_task_flag"] = True
                    else:
                        if 0 == len(task["undo_fwd"]):
                            if 0 != len(task["err_cdn"]) or 0 != len(task["err_fwd"]):
                                log.error("task deal error, id:%s, time:%s, error fwd:%s, error cdn:%s" % 
                                        (task_id, (datetime.datetime.now()-task["time"]).total_seconds(), task["err_fwd"], task["err_cdn"]))
                                task_record_info["err"] += 1
                                db_manager.update_pdns_sync_status(task_id, constants.PDNS_SYNC_STAUS_ERROR, conn=conn)
                                sync_task_dict.pop(task_id)
                            else:
                                db_manager.update_pdns_sync_status(task_id, constants.PDNS_SYNC_STAUS_FINISHED, conn=conn)
                                log.info("task deal success, id:%s, time:%s" % (task_id, (datetime.datetime.now()-task["time"]).total_seconds()))
                                task_record_info["suc"] += 1
                                sync_task_dict.pop(task_id)
                        else:
                            if task["time"] + datetime.timedelta(seconds=360) < datetime.datetime.now():
                                log.error("task deal error, timeout, id:%s, time:%s, error fwd:%s, error cdn:%s, undo fwd:%s" %
                                        (task_id, (datetime.datetime.now()-task["time"]).total_seconds(), task["err_fwd"], task["err_cdn"], task["undo_fwd"]))
                                task_record_info["err"] += 1
                                db_manager.update_pdns_sync_status(task_id, constants.PDNS_SYNC_STAUS_TIMEOUT, conn=conn)
                                sync_task_dict.pop(task_id)
                else:
                    if task["time"] + datetime.timedelta(seconds=300) < datetime.datetime.now():
                        log.error("task deal error, timeout, id:%s, time:%s, error fwd:%s, error cdn:%s, undo cdn:%s" %
                                (task_id, (datetime.datetime.now()-task["time"]).total_seconds(),  task["err_fwd"], task["err_cdn"], task["undo_cdn"]))
                        task_record_info["err"] += 1
                        db_manager.update_pdns_sync_status(task_id, constants.PDNS_SYNC_STAUS_TIMEOUT, conn=conn)
                        sync_task_dict.pop(task_id)

        except:
            log.error("sync_with_pdns error:%s" % traceback.format_exc())

        try:
            if datetime.datetime.now() - task_record_info["time"] >= datetime.timedelta(seconds=60):
                suc_per = 100
                total_count = task_record_info["suc"] + task_record_info["err"]
                if 0 != total_count:
                    suc_per = task_record_info["suc"] * 100.0 / total_count
                task_record_info['percent'] = float("%.2f" % suc_per)
                task_record_info['time'] = task_record_info['time'].strftime("%Y-%m-%d %H:%M:%S")
                output = {"MSG":[task_record_info,], "collection_flag":0}

                log.info("task statistis data:%s" % json.dumps(task_record_info, indent=3, ensure_ascii=False))
                gf = open('logs/pdns-monitor-data.log', 'w')
                gf.write("%s" % json.dumps(output))
                gf.flush()
                gf.close()
                task_record_info = {"err":0, "suc":0, "time":datetime.datetime.now(), "percent":0}
        except:
           log.error("sync_with_pdns error:%s" % traceback.format_exc())



def deal_domain_sync(task, rlt_queue):
    """
    处理与pdns机器的域名同步删除任务,需要先执行cdn机器，然后再执行forward机器，已经在server中排序
    """
    try:
        server = task.get("server")
        param_info = copy.deepcopy(server)
        param_info["url"] = "/del_domain"
        param_info["method"] = "post"
        params = {}
        params["server_type"] = param_info["type"]
        params["domain_list"] = copy.deepcopy(task["tasks"])
        param_info["params"] = params

        # {u'msg': u'cmd error', u'code': u'000', u'success': False, 'agent':ip}
        server_flag = False
        for i in range(5):
            res = http_manager.send_message_to_agent(param_info)
            if False != res and True == res["success"]:
                server_flag = True
                break
            else:
                log.warning("send msg to agent error:%s" % res)
                time.sleep(1)
                continue

        # agent操作结果处理
        rlt_queue.put({"cmd": constants.QUEUE_CMD_RET, "ret_flag":server_flag, "task": task})

    except:
        log.error("server sync domain error:%s, server:%s, tasks:%s" % (traceback.format_exc(), str(server), str(task["tasks"])))
        return False


def deal_server_monitor(task):
    """
    pdns机器状态监控,模块版本采集
    """
    param_info = copy.deepcopy(task.get("server"))
    server_status = {
        "server_type" : param_info["type"],
        "pdns_ip" : param_info["ip"],
        "pdns_id" : param_info["id"],
        "pdns_process" : "offline",
        "pdns_version" : "",
        "agent_version" : "",
        "agent_status" : "offline",
        "gmt_modified" : None
    }
    try:
        param_info["url"] = "/monitor_server"
        param_info["method"] = "post"
        param_info["params"] = {"server_type": param_info["type"]}
        res = http_manager.send_message_to_agent(param_info)
        if False != res:
            server_status["pdns_process"] = res.get("pdns_process", "offline")
            server_status["pdns_version"] = res.get("pdns_version", "")
            server_status["agent_version"] = res.get("agent_version", "")
            server_status["agent_status"] = res.get("agent_status", "offline")
    except:
        log.error("deal server monitor error:%s" % traceback.format_exc())
    
    try:
        if param_info["status"] != server_status["pdns_process"]:
            if "online" == server_status["pdns_process"]:
                log.error("status changed line:on:%s --> %s" % (str(param_info), str(server_status)))
                db_manager.update_pdns_server_status(server_status)
            else: # ("offline" == server_status["pdns_process"]):
                if param_info["gmt_modified"] in (None, ""):
                    server_status["pdns_process"] = param_info["status"]
                    server_status["gmt_modified"] = 'now()'
                    log.info("status changed tmp:%s --> %s" % (str(param_info), str(server_status)))
                    db_manager.update_pdns_server_status(server_status)
                elif param_info["gmt_modified"] + datetime.timedelta(seconds=60) < datetime.datetime.now():
                    log.error("status changed line:off:%s --> %s" % (str(param_info), str(server_status)))
                    db_manager.update_pdns_server_status(server_status)
        else:
            if param_info["gmt_modified"] not in (None, ""):
                server_status["gmt_modified"] = None

                log.info("status changed tmp:%s --> %s" % (str(param_info), str(server_status)))
                db_manager.update_pdns_server_status(server_status)
    except:
        log.error("update_pdns_server_status error:%s" % traceback.format_exc())



def parse_queue_task(index, rlt_queue, task_queue):
    """
    从QUEUE队列中获取单机任务，发送给agent进行处理
    task = {
        "server" : {"ip":***, "port":***, "type":***, "id":***},
        "tasks" : [{
            "id":int(task[0]),
            "zone":zone,
            "domain_name":domain_name,
            "action":"delRr"}, {***}, {***}],
        "action": ,
        "retry_count" : int
    }
    """
    queue = task_queue
    log.info("start process, index:%d, queue id:%d" % (index, id(queue)))

    while True:
        try:
            #task = queue.get(block=True)
            # log.info("queue id get before:%d, size:%d" % (id(queue), queue.qsize()))
            #task = queue.get(timeout=10)
            task = queue.get(block=False)
            if 0 == index:
                log.info("queue id get:%d, size:%d" % (id(queue), queue.qsize()))
            #task = queue.get(block=False, timeout=2)
            action = task.get("action")
            if constants.AGENT_FUNC_DEL_DOMAIN == action:
                deal_domain_sync(task, rlt_queue)
            elif constants.AGENT_FUNC_MONITOR_SERVER_STATUS == action:
                deal_server_monitor(task)
        except Empty, e:
            time.sleep(0.01)
        except:
            log.error("parse_queue_task error:%s" % traceback.format_exc())
            
