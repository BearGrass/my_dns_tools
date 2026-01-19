#!/home/tops/bin/python
#****************************************************************#
# ScriptName: nic_queue_mon.py
# Author: zhaozhi.gzzn@alibaba-inc.com
# Create Date: 2017-05-18
#***************************************************************#

from __future__ import division
import os
import sys
import time
import string
import json
import re
from commands import getstatusoutput

reload(sys)
sys.setdefaultencoding('utf8')
g_lastcheck = time.strftime('%F_%T',time.localtime(time.time()))

info_json = {}
info_json["MSG"] = []

INTERVAL = 2

QUEUE_CNT_TYPE = [ r"RX-receive-queue",
                   r"RX-drop-queue",
                   r"TX-send-queue" ]

def get_count():
    type_portCnt = {}
    type_queueCntList = {}
    cmd = "/home/adns/bin/adns_adm --dpdk-port"
    rc, output = getstatusoutput(cmd)
    for line in output.split('\n'):
        # iterate through different types of counters
        for type_id in range(len(QUEUE_CNT_TYPE)):
            if re.findall(QUEUE_CNT_TYPE[type_id], line):
                cnt_list = re.findall(": \d+", line)
                # iterate through each queue of certain type
                for each_count in cnt_list:
                    count_number = long(each_count.lstrip(":"))
                    type_portCnt[type_id] = type_portCnt.setdefault(type_id, 0) + count_number
                    type_queueCntList.setdefault(type_id, []).append(count_number)
    return type_portCnt, type_queueCntList

def get_speed(prev_type_queueCntList, curr_type_queueCntList,
              prev_type_portCnt, curr_type_portCnt, ts_diff):
    type_queueSpeed = {}
    type_portSpeed = {}
    for type_id in range(len(QUEUE_CNT_TYPE)):
        port_diff = curr_type_portCnt[type_id] - prev_type_portCnt[type_id]
        type_portSpeed[type_id] = round(port_diff / ts_diff)
    for type_id in range(len(QUEUE_CNT_TYPE)):
        perv_queueCntList = prev_type_queueCntList[type_id]
        curr_queueCntList = curr_type_queueCntList[type_id]
        for i in range(len(perv_queueCntList)):
            queue_diff = curr_queueCntList[i] - perv_queueCntList[i]
            if queue_diff > 0:
                type_queueSpeed.setdefault(type_id, []).append( round(queue_diff / ts_diff) )
            else:
                type_queueSpeed.setdefault(type_id, []).append(0)
    return type_queueSpeed, type_portSpeed

def get_qps():
    cmd = "/home/adns/bin/adns_adm --stats"
    rc, output = getstatusoutput(cmd)
    for line in output.split('\n'):
        if re.findall(r"qps", line):
            qps = re.findall("\d+", line)
    return long(qps[0])

prev_ts = time.time()
prev_type_portCnt, prev_type_queueCntList = get_count()
time.sleep(INTERVAL)
curr_ts = time.time()
curr_type_portCnt, curr_type_queueCntList = get_count()
queue_speed_list, port_speed_list = get_speed(prev_type_queueCntList, curr_type_queueCntList,
                                              prev_type_portCnt, curr_type_portCnt, curr_ts - prev_ts)
info_json["MSG"].append(dict(checkname = "port_drop_rate", \
                            count = port_speed_list[1], \
                            percentage = round(port_speed_list[1] / (get_qps()+1) , 3), \
                            last_check = g_lastcheck))
info_json["MSG"].append(dict(checkname = "port_rx_fps", \
                            count = port_speed_list[0], \
                            percentage = round(port_speed_list[0], 3), \
                            last_check = g_lastcheck))
info_json["MSG"].append(dict(checkname = "port_drop_fps", \
                            count = port_speed_list[1], \
                            percentage = round(port_speed_list[1], 3), \
                            last_check = g_lastcheck))
info_json["MSG"].append(dict(checkname = "port_tx_fps", \
                            count = port_speed_list[2], \
                            percentage = round(port_speed_list[2], 3), \
                            last_check = g_lastcheck))
print port_speed_list
for type_id in range(len(QUEUE_CNT_TYPE)):
    print queue_speed_list[type_id]
    for i in range(len(queue_speed_list[type_id])):
        info_json["MSG"].append(dict(checkname = QUEUE_CNT_TYPE[type_id]+"-"+str(i), \
                                    count = queue_speed_list[type_id][i], \
                                    percentage = round(queue_speed_list[type_id][i], 3), \
                                    last_check = g_lastcheck))

info_json["collection_flag"] = 0
#print info_json
