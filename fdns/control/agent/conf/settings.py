#coding=utf-8
__author__ = 'weiguo.cwg'

import os

LOG_HANDLE_NAME = "pdns-agent"
LOGGING_PATH = "/home/work/pdns-agent/logs"
if not os.path.exists(LOGGING_PATH):
    os.makedirs(LOGGING_PATH)

PDNS_CMD_FORWARD = "/work/dpdk_fwrd/scripts/fwd_deldata.sh"
PDNS_CMD_REDIS = "/home/work/redis/scripts/rds_deldata.sh"
PDNS_CMD_CDN = "/home/work/scripts/bind_deldata.sh"

#agent的版本号
GIT_REF = '@@GIT_REF@@'
GIT_SHA1 = '@@GIT_SHA1@@'