#!/usr/bin/python
# -*- coding: utf-8 -*-


import os
import sys
from multiprocessing import Process
from optparse import OptionParser
from adns_resolver import RESOLVER
from adns_log import LOG




def adns_query(log, resolver, result, vip_server):
    msg = "-------------------ADNS Query-------------------"
    log.SHOW(msg)
        
    for domain in result:
        typemap = result[domain]
        
        for type in typemap:
            viewmap = typemap[type]
            
            for view in viewmap:
                rcode = resolver.get_dig_rcode(vip_server, domain, type, view) 
                
          
def record_value_to_type(value):
    map = {
        "1": "A",
        "2": "NS",
        "5": "CNAME",
        "6": "SOA",
        "12": "PTR",
        "15": "MX",
        "16": "TXT",
        "28": "AAAA",
        "33": "SRV",
        "255": "ANY"     
    } 
    
    if (map.has_key(value)):
        return map[value]
    else:
        return value + "-NOsupported"


#18-06-2015 09:00:02.562 [INFO]: 61.220.1.11:56392->140.205.228.18:53, qname: zt.ycwb.com., qtype: 1, view:OVERSEA, edns:0 
def adns_anaylse_file(log, result, filename):
    fd = open(filename)
    linelist = fd.readlines()
    fd.close()
  
    for line in linelist:
        itemlist = line.split()
        if (len(itemlist) < 9):
            continue
        
        qname = itemlist[5][:-1]                         #zt.ycwb.com.,
        qtype = record_value_to_type(itemlist[7][:-1])   #'1,'
        view = itemlist[9][:-1]            #view:OVERSEA,
            
        if (result.has_key(qname) == False):
            result[qname] = {}
            
        typemap = result[qname] 
        if (typemap.has_key(qtype) == False):
            typemap[qtype] = {}  
        
        viewmap = typemap[qtype]
        if (viewmap.has_key(view) == False):
            viewmap[view] = -1            
    #for ends

        
if __name__ == "__main__":
    usage = "usage: %prog [option]"
    parser = OptionParser(usage)
    parser.add_option("--log_file", dest="log_file", default="etc/adns_query.log", help="set the query log")
    
    parser.add_option("--old_version_vip", dest="old_version_vip", default="10.105.208.166", help="set the vip of adns old version")
    parser.add_option("--new_version_vip", dest="new_version_vip", default="10.105.208.182", help="set the vip of adns new version")
     
    parser.add_option("--view_map_file", dest="view_map_file", default="etc/view_name_id.map", help="set the view map file")  
    parser.add_option("--ip_range_file", dest="ip_range_file", default="etc/ip_range.map", help="set the ip range map file")  
   
    (options, args) = parser.parse_args()

    log_file = options.log_file 
    old_version_vip = options.old_version_vip
    new_version_vip = options.new_version_vip
    view_map_file = options.view_map_file
    ip_range_file = options.ip_range_file
       
    log = LOG()
    log.CLEANUP()    
    resolver = RESOLVER(view_map_file, ip_range_file, old_version_vip, new_version_vip)
    
    result = {}
    adns_anaylse_file(log, result, log_file)
    adns_query(log, resolver, result, new_version_vip)

