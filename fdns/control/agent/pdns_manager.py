#coding=utf-8
__author__ = 'weiguo.cwg'

import logging
import traceback
import commands

from conf import settings,constants
log = logging.getLogger(settings.LOG_HANDLE_NAME)

class pdns_manager(object):
    """
    负责与本地pdns中域名的增删改操作，目前只有删除的需求，添加走递归逻辑获取
    """

    @staticmethod
    def del_domain(server_type, domain_list):
        """
        [   {
                "id":int(task[0]),
                "zone":zone,
                "domain_name":domain_name,
                "action":"del"
            },{},{}
        ]
        """
        CMD_FORMAT = "%s %s 1"
        result = {"error":[], "ok":[]}
        for task in domain_list:
            try:
                if "del" != task["action"]:
                    log.warning("unknow task action:%s" % str(task["action"]))
                    continue

                cmd = None
                if constants.SERVER_TYPE_FWD == server_type:
                    cmd = CMD_FORMAT % (settings.PDNS_CMD_FORWARD, task["domain_name"])
                elif constants.SERVER_TYPE_REDIS == server_type:
                    cmd = CMD_FORMAT % (settings.PDNS_CMD_REDIS, task["domain_name"])
                elif constants.SERVER_TYPE_CDN == server_type:
                    cmd = CMD_FORMAT % (settings.PDNS_CMD_CDN, task["domain_name"])
                else:
                    log.warning("unknow server type:%s, task:%s" % (server_type, str(task)))
                    continue

                log.info("cmd:%s" % cmd)
                status, response = commands.getstatusoutput(cmd)
                log.info("status:%s, response:%s" % (status, response))
                if 0 == status:
                    result["ok"].append(task["id"])
                else:
                    result["error"].append(task["id"])
            except:
                log.error("del_domain:%s" % traceback.format_exc())
                result["error"].append(task["id"])
        
        return result


