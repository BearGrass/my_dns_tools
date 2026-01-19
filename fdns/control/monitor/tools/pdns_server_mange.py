#coding=utf-8
__author__ = 'weiguo.cwg'
import os, sys


def usage():
    print "/home/tops/bin/python  /home/work/pdns-monitor/tools/pdns_server_mange.py query_server"
    print "/home/tops/bin/python  /home/work/pdns-monitor/tools/pdns_server_mange.py add_server"
    print "/home/tops/bin/python  /home/work/pdns-monitor/tools/pdns_server_mange.py del_server"


PROJECT_PATH = os.path.dirname(os.path.dirname(__file__))
if "/home/work/pdns-monitor" != PROJECT_PATH:
    usage()
    os._exit(-1)

sys.path.append(PROJECT_PATH)

import logging
import traceback
import sys

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                    datefmt='%a, %d %b %Y %H:%M:%S',
                    filename="%s/logs/pdns_server.log" % PROJECT_PATH,
                    filemode='a')
log = logging.getLogger("pdns_server")

from util.db_helper import DbHelper
from conf.settings import DB_CONFIG
from conf import server_list



def connect_adms_db():
    """
    连接默认的DB
    """
    HOST = DB_CONFIG.get("host")
    USER = DB_CONFIG.get("user")
    PASSWORD = DB_CONFIG.get("passwd")
    PORT = int(DB_CONFIG.get("port"))
    DB = DB_CONFIG.get("dbname")
    # DEFAULT_CHARSET = settings.DB_CONFIG.get("DEFAULT_CHARSET")

    db_handler = DbHelper(HOST, USER, PASSWORD, DB, port=PORT)
    return db_handler


def add_pdns_server():
    """
    根据conf/server_list中的配置，更新db.pdns_server表信息
    """
    db_handler = None
    try:
        db_handler = connect_adms_db()
        log.info("add pdns server list:%s" % str(server_list.pdns_servers_add))
        print "add server list:"
        for server in server_list.pdns_servers_add:
            server_info = server.strip(",").split(",")
            log.info("serve info:%s" % str(server_info))
            s_info = {"type":server_info[0], "ip":server_info[1], "host":server_info[1], "port":9999}
            if 3 == len(server_info):
                s_info["host"] = server_info[2]
            elif 4 <= len(server_info):
                s_info["host"] = server_info[2]
                s_info["port"] = int(server_info[3])

            sql = "select * from pdns_server where ip='%s'" % s_info["ip"]
            log.info("sql:%s" % sql)
            res = db_handler.execute(sql)
            if 0 < len(res):
                log.error("server:%s already in pdns_server table" % str(res))
                print "already in db,'%s,%s,%s,%s'" % (s_info["type"],s_info["ip"],s_info["host"],s_info["port"])
                continue

            sql = "insert into pdns_server (id, ip, host, port, type, status, gmt_created, gmt_modified, pdns_version, agent_version, agent_status)\
                  values(id, '%s', '%s', %d, '%s', 'offline', now(), now(), NULL, NULL, 'offline')" %\
                  (s_info["ip"], s_info["host"], s_info["port"], s_info["type"])
            log.info("add sql:%s" % sql)
            db_handler.execute(sql)
            print "'%s,%s,%s,%s'" % (s_info["type"],s_info["ip"],s_info["host"],s_info["port"])
        return True
    except:
        log.error("add_pdns_server, error:%s" % traceback.format_exc())
        return False
    finally:
        if None != db_handler:
            db_handler.close()


def del_pdns_server():
    """
    根据conf/server_list中的配置，更新db.pdns_server表信息
    """
    db_handler = None
    try:
        db_handler = connect_adms_db()
        log.info("del pdns server list:%s" % str(server_list.pdns_servers_del))
        print "del server list:"
        for server in server_list.pdns_servers_del:
            server_info = server.strip(",").split(",")
            log.info("server_info:%s" % str(server_info))
            s_info = {"type":server_info[0], "ip":server_info[1]}

            sql = "select * from pdns_server where ip='%s' and `type`='%s'" % (s_info["ip"], s_info["type"])
            log.info("sql:%s" % sql)
            res = db_handler.execute(sql)
            if 0 == len(res):
                log.error("no server:%s,%s in pdns_server table" % (s_info["ip"], s_info["type"]))
                print "no data in db::,'%s,%s'" % (s_info["type"], s_info["ip"])
                continue
            elif 1 == len(res):
                sql = "delete from pdns_server where ip='%s' and `type`='%s' limit 1" % (s_info["ip"], s_info["type"])
                log.info("del sql:%s" % sql)
                db_handler.execute(sql)
                print "'%s,%s'" % (s_info["type"], s_info["ip"])
            else:
                log.error("server:%s error in pdns_server table" % str(res))
                return False
        return True
    except:
        log.error("del_pdns_server, error:%s" % traceback.format_exc())
        return False
    finally:
        if None != db_handler:
            db_handler.close()

def query_pdns_server():
    """
    查询pdns_server表中机器列表
    """
    db_handler = None
    try:
        db_handler = connect_adms_db()
        sql = "select * from pdns_server limit 500"
        log.info("sql:%s" % sql)
        s_list = db_handler.execute(sql)
        print "current server list:"
        for s in s_list:
            log.info("type:%s, ip:%s, host:%s, port:%d, status:%s, agent status:%s, pdns_version:%s" % (
                s["type"],s["ip"],s["host"],s["port"],s["status"],s["agent_status"],s["pdns_version"]))
            print "'%s,%s,%s,%s'" % (s["type"],s["ip"],s["host"],s["port"])
    except:
        log.error("query_pdns_server, error:%s" % traceback.format_exc())
    finally:
        if None != db_handler:
            db_handler.close()


def main():
    params = sys.argv
    if 2 != len(params):
        usage()
        return

    log.info("cmd:%s" % params)
    if "add_server" == params[1]:
        add_pdns_server()
    elif "del_server" == params[1]:
        del_pdns_server()
    elif "query_server" == params[1]:
        query_pdns_server()
    else:
        log.info("unknow cmd:%s" % params[1])
        usage()

if __name__ == "__main__":
    main()

