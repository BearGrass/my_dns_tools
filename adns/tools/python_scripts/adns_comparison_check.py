#!/usr/bin/python
# -*- coding: utf-8 -*-


import os
import sys
import subprocess
import os
from multiprocessing import Process
from optparse import OptionParser
from adns_resolver import RESOLVER
from adns_log import LOG


def adns_query(log, resolver, result):
    msg = "-------------------ADNS Query-------------------"
    log.SHOW(msg) 

    for zone in result:
        domain_map = result[zone]
        for domain in domain_map:
            # use -k to force all-rr, could it be useful?
            #adns_cmd = "sudo /home/adns/bin/adns_adm -k --zone %s --domain %s --mode 1"   %(zone, domain)
            #cmd1 = 'ssh root@%s "%s"' % ("10.98.110.57", adns_cmd) #TODO, no manage-IP be passed inside
            #cmd2 = 'ssh root@%s "%s"' % ("10.98.110.58", adns_cmd)

            #proc = subprocess.Popen(cmd1, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            #(cmd_stdout, cmd_stderr) = proc.communicate()
            #if proc.returncode != 0 :
            #    print cmd_stderr
            #proc = subprocess.Popen(cmd2, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            #(cmd_stdout, cmd_stderr) = proc.communicate()
            #if proc.returncode != 0 :
            #    print cmd_stderr

            wild_domain_flag = 0
            if (domain.find("*.") != -1):
                wild_domain_flag = 1
                domain = "anytest." + ".".join(domain.split('.')[1:]) 

            resolver.query_edns(domain, wild_domain_flag)
#             view_map = domain_map[domain] 
#
#             for view_name in view_map: 
#                 type_map = view_map[view_name]
#       
#                 for type in type_map:          
#                     rr_map = type_map[type]                                                    
#                     resolver.query_edns(domain, rr_map, type)
                #for ends(type)
            #for ends(view)
        #for ends (domain)
    #for ends(zone)



#(SOA)   A iauto360.cn. 3600 dns31157.hichina.com. hostmaster.hichina.com. 2015012914 3600 1200 3600 360
#(A)     a iauto360.cn. gis-api.iauto360.cn. default IN A 600 58.67.203.8 1
#(AAAA)  a 911sky.com. www.911sky.com. default IN AAAA 600 2605:f700:40:c00::b6ea:8f48

#(CNAME) a iauto360.cn. test-mt.iauto360.cn. default IN CNAME 600 dyn-ip.iauto360.cn.
#(NS)    a iauto360.cn. iauto360.cn. default IN NS 86400 dns31.hichina.com.
#(PTR)   a 127.194.170.in-addr.arpa. 76.127.194.170.in-addr.arpa.  default IN PTR 600 www.taobao.com

#(MX)    a sunhometj.com. sunhometj.com. default IN MX 600 10 mx02.mail.alibaba.com.

#(TXT)   a qianchen123.com. qianchen123.com. default IN TXT 600 v=spf1 include:spf.mxhichina.com -all
#(SRV)   a ecscloud.com.cn. _sip._tls.ecscloud.com.cn. default IN SRV 3600 1 100 443 sipdir.online.partner.lync.cn. 
def adns_anaylse_file(log, result, filename):
    fd = open(filename)
    linelist = fd.readlines()
    fd.close()
  
    for line in linelist:
        itemlist = line.split()
        if (len(itemlist) < 6):
            continue

        opcode = itemlist[0]
        if (opcode == "A"):
            zone = itemlist[1].lower()    #iauto360.cn.
            if (result.has_key(zone) == False):
                result[zone] = {}
            continue      
        elif (opcode == "a"):
            zone = itemlist[1].lower()     #iauto360.cn.
            domain = itemlist[2].lower()   #gis-api.iauto360.cn.
            view = itemlist[3]             #default/BAIDU
            type = itemlist[5]
            
            if (type == "A"):
                record = itemlist[7].lower()
            elif (type == "AAAA"):
                record = itemlist[7].lower()                
            elif (type == "CNAME"):
                record = itemlist[7].lower()
            elif (type == "NS"):
                record = itemlist[7].lower()
            elif (type == "PTR"):
                record = itemlist[7].lower()               
            elif (type == "MX"):
                record = itemlist[8].lower()
            elif (type == "TXT"):
                record = " ".join(itemlist[7:]).lower()
            elif (type == "SRV"):
                record = itemlist[10].lower()
            else:
                continue
       
        #check zone
        if (result.has_key(zone) == False):
           error = "[adns_anaylse_file]: Zone does not exist when add record, line = %s, filename = %s!"       %(line[:-1], filename)
           print error
           log.ERROR(error)
           result[zone] = {}
        
        #handle domain
        domain_map = result[zone]
        if (domain_map.has_key(domain) == False):
          domain_map[domain] = {}
        
        #handle view
        view_map = domain_map[domain]
        if (view_map.has_key(view) == False):
          view_map[view] = {}
                
        #handle record 
        type_map = view_map[view]
        if (type_map.has_key(type) == False):
          type_map[type] = {}  

        rr_map = type_map[type]  
        if (rr_map.has_key(record) == False):
          rr_map[record] = 0
    #for ends


def adns_analyse(index, root_dir, start_dir, end_dir, log, resolver):     
    if os.path.isdir(root_dir):
        list = os.listdir(root_dir)
        list.sort(lambda x,y:cmp(int(x.split("_")[0]), int(y.split("_")[0])))
    else:
        error = "[adns_analyse]: root_dir %s is not a dir!"         %(root_dir)
        log.ERROR(error)
        sys.exit()
  
    if (start_dir == None):
        start_flag = 1
    else:
        start_flag = 0 
  
    end_flag = 0      
    result = {}
    for subdir in list:
        if (subdir == start_dir):        
            start_flag = 1
      
        if (start_flag == 0):
            continue 
         
        if (subdir == end_dir):
            end_flag = 1
    
        if (end_flag == 1):
            break
         
        filepath = os.path.join(root_dir, subdir)
        msg = "\n[adns_analyse]: path = %s, index = %d"             %(filepath, index)
        log.SHOW(msg)
    
        if os.path.isdir(filepath):                      #/home/hejun.hj/20150304_realdata/adns_db_file/0        
            sublist = os.listdir(filepath)
            sublist.sort(lambda x,y:cmp(int(x.split("_")[0]), int(y.split("_")[0])))
        
            for line in sublist:          
                filename = os.path.join(filepath, line)  #/home/hejun.hj/20150304_realdata/adns_db_file/0/a.file
                info = "[adns_analyse]: filename = %s, index = %d"  %(filename, index)
                log.INFO(info)
                
                adns_anaylse_file(log, result, filename) 
        else:
            file = ".".join(line.split(".")[:-1])
            error = "[adns_analyse]: Can not be here, file = %s"    %(file)
            log.ERROR(error)
            sys.exit()

    adns_query(log, resolver, result)
    #for ends  

        
if __name__ == "__main__":
####
    usage = "usage: %prog [option]"
    parser = OptionParser(usage)
    parser.add_option("-r", "--root_dir", dest="root_dir", default="online/", help="set the root directory")
    parser.add_option("-s", "--start_dir", dest="start_dir", help="set the start directory")
    parser.add_option("-e", "--end_dir", dest="end_dir", help="set the end directory")
    parser.add_option("-p", dest="process_num", default=10, help="set the process_num") 
    
    parser.add_option("--old_version_vip", dest="old_version_vip", default="140.205.81.1", help="set the vip of adns old version")
    parser.add_option("--new_version_vip", dest="new_version_vip", default="140.205.81.3", help="set the vip of adns new version")
     
    parser.add_option("--view_map_file", dest="view_map_file", default="etc/view_name_id.map", help="set the view map file")  
    parser.add_option("--ip_range_file", dest="ip_range_file", default="etc/ip_range.map", help="set the ip range map file")  
   
    (options, args) = parser.parse_args()
   
    root_dir = options.root_dir         
    start_dir = options.start_dir
    end_dir = options.end_dir 
    process_num = int(options.process_num) 
    old_version_vip = options.old_version_vip
    new_version_vip = options.new_version_vip
    view_map_file = options.view_map_file
    ip_range_file = options.ip_range_file
       
    log = LOG()
    log.CLEANUP()    

####
    resolver = RESOLVER(view_map_file, ip_range_file, old_version_vip, new_version_vip)
    #adns_analyse(root_dir, start_dir, end_dir, log, resolver)
    
    if (start_dir != None):
      start_index = int(start_dir)
    else:
      start_index = 0
    
    if (end_dir != None):
      end_index = int(end_dir)
    else:
      end_index = 200  

    interval = (end_index - start_index) / process_num
    process_queue = []
    for index in range(process_num):
        try:
            if (interval != 0):
              start_dir = str(index * interval)
              end_dir = str((index + 1) * interval)
            else:
              start_dir = str(index)
              end_dir = str(index + 1) 
              
            pid = Process(target=adns_analyse, args=(index, root_dir, start_dir, end_dir, log, resolver))
        except:
            error = "[MAIN]: Process Failed!"
            log.ERROR(error)
            sys.exit()             
        else:
            process_queue.append(pid)
            
    #for ends        
    for pid in process_queue:
        pid.start()

    for pid in process_queue:
        pid.join()



