#!/usr/bin/python
# -*- coding: utf-8 -*-


import os
import termcolor


class LOG():
    
    def __init__(self):
        pass
    
    
    def CLEANUP(self):
        logpath = "logs/"
        if (os.path.exists(logpath) == False):
            os.makedirs(logpath)
  
        error_log = logpath + "error.log"
        if os.path.isfile(error_log):   
            os.remove(error_log)

        query_log = logpath + "query.log"
        if os.path.isfile(query_log):   
            os.remove(query_log)


    def SHOW(self, buf, color="green"):
        print termcolor.colored(buf, color) 

   
    def INFO(self, buf, cr=True):
        if cr:
            print termcolor.colored(buf, "grey")
        else:
            print termcolor.colored(buf, "grey"),


    def ERROR(self, buf, cr=True):
        if cr:
            print termcolor.colored(buf, "red")
        else:
            print termcolor.colored(buf, "red"),
    
        filename = "logs/error.log" 
        fd = open(filename, "a+") 
        fd.write(buf + "\n")  
        fd.close() 

    
    def RECORD(self, buf):
        filename = "logs/query.log" 
        fd = open(filename, "a+") 
        fd.write(buf + "\n")  
        fd.close() 
     



    