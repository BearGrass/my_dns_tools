#coding=utf-8
__author__ = 'weiguo.cwg'

import logging
import traceback
import time
import random
import datetime


from conf import settings,constants
from util.db_helper import DbHelper

log = logging.getLogger(constants.LOG_HANDLE_NAME)


def connect_adms_db():
    """
    连接默认的DB
    """
    HOST = settings.DB_CONFIG.get("host")
    USER = settings.DB_CONFIG.get("user")
    PASSWORD = settings.DB_CONFIG.get("passwd")
    PORT = int(settings.DB_CONFIG.get("port"))
    DB = settings.DB_CONFIG.get("dbname")
    # DEFAULT_CHARSET = settings.DB_CONFIG.get("DEFAULT_CHARSET")

    db_handler = DbHelper(HOST, USER, PASSWORD, DB, port=PORT)
    return db_handler



def lock_base(lock_name):
    time.sleep(random.randint(1, 9)*random.randint(1, 9)*1.0/100)
    conn = connect_adms_db()
    sql = "select name, active_ip, update_time from locks where name='%s';" % lock_name
    log.info("sql:%s" % sql)
    res = conn.execute(sql)[0]
    conn.close()
    return res

def hb_base(ip, now, lock_name, **attrs):
    attrs['active_ip'] = ip
    attrs['update_time'] = now

    conn = connect_adms_db()
    sql = "update locks set active_ip='%(ip)s', update_time='%(update_time)s' " \
          "where name='%(name)s'" % {'ip': ip, 'update_time': now, 'name': lock_name}
    log.info("sql:%s" % sql)
    conn.execute(sql)
    conn.close()


def le(lock_rec):
    if lock_rec:
        log.info('locked:%s' % lock_rec)
    else:
        log.info('unlock')


def update_pdns_sync_status(id, status, conn=None):
    """
    更新adms_task.pdns_sync_status值
    """
    new_conn = False
    if None == conn:
        conn = connect_adms_db()
        new_conn = True

    sql = "update adms_task set pdns_sync_status=%d where id=%d limit 1" % (status, id)
    log.info("sql:%s" % sql)
    res = conn.execute(sql)
    if 0 != len(res):
        log.error("update pdns_sync_status sql:%s error:%s" % (sql, res))

    if True == new_conn:
        conn.close()



def get_sync_task_lock(conn):
    """
    获取sync更新的锁
    """
    try:
        sql = "insert into locks values('monitor_pdns_task.lock', '%s', now(), id)" % (settings.LOCAL_IP)
        log.info("sql:%s" % sql)
        res = conn.execute(sql)
        if 0 == len(res):
            return True
    except:
        sql = "select * from locks where name='monitor_pdns_task.lock'"
        log.info("sql:%s" % sql)
        res = conn.execute(sql)
        if 1 != len(res):
            sql = "delete from locks where name='monitor_pdns_task.lock' limit 1"
            log.info("sql:%s" % sql)
            res = conn.execute(sql)
        else:
            if res[0]["update_time"] + datetime.timedelta(seconds=30) < datetime.datetime.now():
                sql = "delete from locks where name='monitor_pdns_task.lock' limit 1"
                log.info("sql:%s" % sql)
                res = conn.execute(sql)

        return False

def update_sync_task_time(conn):
    """
    更新获取任务的时间
    """
    try:
        sql = "update locks set update_time=now() where name='monitor_pdns_task.lock'"
        log.info("sql:%s" % sql)
        conn.execute(sql)
        return True
    except:
        log.error("update update_sync_task_time error, %s" % traceback.format_exc() )
        return False

def delete_sync_task_lock(conn):
    try:
        sql = "delete from locks where name='monitor_pdns_task.lock' limit 1"
        log.info("sql:%s" % sql)
        conn.execute(sql)
        return True

    except:
        log.error("delete_sync_task_lock error, %s" % traceback.format_exc() )
        return False



def get_pdns_servers(conn, status="online"):
    """
    从pdns_server表中获取server信息
    """
    if status in (None, ""):
        sql = "select id,ip,port,type,status,gmt_modified from pdns_server"
    else:
        sql = "select id,ip,port,type,status,gmt_modified from pdns_server where status='%s'" % status
    log.info("sql:%s" % sql)
    servers = conn.execute(sql)
    server_list = []
    for server in servers:
        if server["type"] not in (constants.SERVER_TYPE_FWD, constants.SERVER_TYPE_REDIS, constants.SERVER_TYPE_CDN):
            continue
        server_list.append(server)

    return server_list


def update_pdns_server_status(server_status):
    """
    更新adms_task.pdns_server_status值
    """
    try:
        conn = connect_adms_db()
        if  server_status["gmt_modified"] in (None, ""):
            sql = "update pdns_server set status='%s', pdns_version='%s', agent_version='%s', agent_status='%s', gmt_modified=NULL where id=%d and ip='%s' limit 1" %\
                  (server_status["pdns_process"], server_status["pdns_version"], server_status["agent_version"],server_status["agent_status"], 
                          server_status["pdns_id"], server_status["pdns_ip"])
        else:
            sql = "update pdns_server set status='%s', pdns_version='%s', agent_version='%s', agent_status='%s', gmt_modified=now() where id=%d and ip='%s' limit 1" %\
                  (server_status["pdns_process"], server_status["pdns_version"], server_status["agent_version"],server_status["agent_status"], 
                          server_status["pdns_id"], server_status["pdns_ip"])

        log.info("sql:%s" % sql)
        res = conn.execute(sql)
        if 0 != len(res):
            log.error("update pdns_server_status sql error:%s" % str(res))

        conn.close()
    except:
        log.error("update_pdns_server_status error:%s" % traceback.format_exc())
