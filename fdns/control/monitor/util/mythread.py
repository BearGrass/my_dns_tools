# -*- coding:utf-8 -*-
import threading
class MyThread(object):
    def __init__(self, func_list=None):
    #所有线程函数的返回值append
        self.reps = list()
        self.func_list = func_list
        self.threads = []

    def set_thread_func_list(self, func_list):
        """
        @note: func_list是一个list，每个元素是一个dict，有func和args两个参数
        """
        self.func_list = func_list

    def start(self):
        """
        @note: 启动多线程执行，并阻塞到结束
        """
        self.threads = []
        self.reps = list()
        for func_dict in self.func_list:
            if func_dict["args"]:
                new_arg_list = []
                new_arg_list.append(func_dict["func"])
                for arg in func_dict["args"]:
                    new_arg_list.append(arg)
                new_arg_tuple = tuple(new_arg_list)
                t = threading.Thread(target=self.trace_func, args=new_arg_tuple)
            else:
                t = threading.Thread(target=self.trace_func, args=(func_dict["func"],))
            self.threads.append(t)
        for thread_obj in self.threads:
            thread_obj.start()
        for thread_obj in self.threads:
            thread_obj.join()

    def ret_value(self):
        """
        @note: 所有线程函数的返回值
        """
        return self.reps
    def trace_func(self, func, *args, **kwargs):
        """
        @note:替代profile_func，新的跟踪线程返回值的函数，对真正执行的线程函数包一次函数，以获取返回值
        """
        ret = func(*args, **kwargs)
        self.reps.append(ret)
        return self.reps

import time
def send(result, id):
    if id in (1,2,4):
        time.sleep(id*2)
        result["ERROR"].append(id)
    else:
        result["OK"].append(id)

    print "id:%s, result:%s" % (id, str(result))


def test():
    print "start test"
    result = {"OK": [], "ERROR": []}

    g_func_list = []
    mt = MyThread()
    for i in range(15):
        g_func_list.append({"func": send, "args": (result, i)})
    mt.set_thread_func_list(g_func_list)
    mt.start()
    print "end test"


# if __name__ == "__main__":
#     test()