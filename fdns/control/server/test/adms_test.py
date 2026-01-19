# coding=utf-8
import sys
import json
import requests
import copy

from settings import *


REQUEST_TEMPLATE = {
        "appId": "test",
        "appKey": "23AE809DDACAF96AF0FD78ED04B6A265E05AA257",
    }

def get_cur_func():
    return sys._getframe().f_back.f_code.co_name


def test_del_rr():
    func_name = get_cur_func()
    print "**************** %s start" % func_name
    param = copy.deepcopy(REQUEST_TEMPLATE)
    param["zone"] = TEST_ZONE
    param["data"] = [TEST_DOMAIN1]
    url = "%s/%s" % (TEST_URL, "api/rr/delRr")
    print url
    print json.dumps(param, indent=3)
    response = requests.post(url, data=json.dumps(param))
    print response.text
    print "**************** %s end" % func_name

def test_add_user():
    func_name = get_cur_func()
    print "**************** %s start" % func_name

    #不设置为superuser
    param = copy.deepcopy(REQUEST_TEMPLATE)
    param["config_app_id"] = 'xh'
    url = "%s/%s" % (TEST_URL, "api/app_user/add_app_user")
    print url
    print json.dumps(param, indent=3)
    response = requests.post(url, data=json.dumps(param))
    print response.text
    print "**************** %s end" % func_name

    #设置为superuser
    param = copy.deepcopy(REQUEST_TEMPLATE)
    param["config_app_id"] = 'zz'
    param["superuser"] = 1
    url = "%s/%s" % (TEST_URL, "api/app_user/add_app_user")
    print url
    print json.dumps(param, indent=3)
    response = requests.post(url, data=json.dumps(param))
    print response.text
    print "**************** %s end" % func_name

def test_del_user():
    func_name = get_cur_func()
    print "**************** %s start" % func_name
    #不设置为superuser
    param = copy.deepcopy(REQUEST_TEMPLATE)
    param["config_app_id"] = 'baihe.zbh'
    url = "%s/%s" % (TEST_URL, "api/app_user/delete_app_user")
    print url
    print json.dumps(param, indent=3)
    response = requests.post(url, data=json.dumps(param))
    print response.text
    print "**************** %s end" % func_name

if __name__ == "__main__":
    test_del_rr()
    #test_add_user()
    #test_del_user()