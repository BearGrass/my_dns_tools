#coding=utf-8
__author__ = 'weiguo.cwg'

import logging
import traceback
import json
import requests
 

from conf import constants


log = logging.getLogger(constants.LOG_HANDLE_NAME)


def send_message_to_agent(param_info):
    # method="post"
    try:
        url = "http://%(HOST)s:%(PORT)s%(URL)s" % {"HOST": param_info['ip'],
                "PORT": param_info["port"], "URL": param_info["url"]}
        #log.info("url:%s" % url)
        method = param_info.get("method", "post")
        params = param_info.get("params", {})
        if "GET" == method.upper():
            resopnse = requests.get(url, data=json.dumps(params), timeout=3)
        else:
            resopnse = requests.post(url, data=json.dumps(params), timeout=3)
        resopnse_info = resopnse.json()
        resopnse_info["agent"] = param_info['ip']
        if True != resopnse_info["success"]:
            log.error("resopnse info error:%s" % resopnse_info)
        #log.info("resopnse info:%s" %  str(resopnse_info))

        return resopnse_info
    except:
        log.error("send_message_to_agent error:%s %d, %s" % (param_info['ip'], param_info['port'], traceback.format_exc()))
        return False



