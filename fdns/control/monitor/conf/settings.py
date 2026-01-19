#coding=utf-8
__author__ = 'weiguo.cwg'

import os
import platform
import socket
from multiprocessing import Queue


SYSTEM_TYPE = platform.architecture()
if "windows" in str(SYSTEM_TYPE).lower():
#日志
    LOGGING_PATH = "D:\\adms"
else:
    LOGGING_PATH = "./logs"


LOCAL_IP = socket.gethostbyname(socket.gethostname())

#DB_CONFIG = {"host":"10.249.193.170", "user":"HICHINA_ADMS_APP", "passwd":"123456", "dbname":"HICHINA_ADMS_APP", "port":8501}
DB_CONFIG = {"host":"10.194.208.38", "user":"hichina_adms_n", "passwd":"hichina_adms_n_ww", "dbname":"hichina_adms", "port":3306}

MULTIPROCESS_NUM = 100

