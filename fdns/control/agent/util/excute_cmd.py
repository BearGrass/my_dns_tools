# coding=utf-8

'''
Created on 2014年11月7日
@author: weiguo.cwg
'''

import shlex
import datetime
import subprocess
import time
import logging

log = logging.getLogger("adms-agent")

def execute_command(cmd_str, cwd=None, timeout=None, shell=False):
    """
    执行一个SHELL命令
    封装了subprocess的Popen方法, 支持超时判断，支持读取stdout和stderr
    参数:
        cwd: 运行命令时更改路径，如果被设定，子进程会直接先更改当前路径到cwd
        timeout: 超时时间，秒，支持小数，精度0.1秒
        shell: 是否通过shell运行
    Returns: return_code
    Raises:  Exception: 执行超时
    """
    if shell:
        cmd_str_list = cmd_str
    else:
        cmd_str_list = shlex.split(cmd_str)
    if timeout:
        end_time = datetime.datetime.now() + datetime.timedelta(seconds=timeout)

    #没有指定标准输出和错误输出的管道，因此会打印到屏幕上；
    sub = subprocess.Popen(cmd_str_list, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=shell, bufsize=4096)

    #subprocess.poll()方法：检查子进程是否结束了，如果结束了，设定并返回码，放在subprocess.returncode变量中
    while sub.poll() is None:
        time.sleep(0.1)
        if timeout:
            if end_time <= datetime.datetime.now():
                sub.terminate()
                return (-1, "cmd timeout")
                #raise Exception("Timeout：%s" % str(cmd_str_list))
            else:
                pass
                #log.debug("no respone for cmd:%s" % cmd_str)
                
    fd = sub.stdout
    line = str(fd.readline()).strip("\n")
    fd.close()
    return (sub.returncode, line)

if __name__=="__main__":
    print execute_command("adns_adms -s")
