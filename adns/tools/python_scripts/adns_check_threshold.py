#!/usr/bin/python
# -*- coding: utf-8 -*-


import os,sys,re,time
import random
import threading
import termcolor
from optparse import OptionParser
 

def SHOW(buf, color="green"):
  print termcolor.colored(buf, color) 

   
def INFO(buf, cr=True):
  if cr:
    print termcolor.colored(buf, "grey")
  else:
    print termcolor.colored(buf, "grey"),


def ERROR(buf, cr=True):
  if cr:
    print termcolor.colored(buf, "red")
  else:
    print termcolor.colored(buf, "red"),
    
  filename = "logs/error.log" 
  fd = open(filename, "a+") 
  fd.write(buf + "\n")  
  fd.close() 
  return 0 
 

def CLEAN_LOG():
  logpath = "logs/"
  if (os.path.exists(logpath) == False):
    os.makedirs(logpath)
  
  error_log = logpath + "error.log"
  if os.path.isfile(error_log):   
    os.remove(error_log)


def adns_parse_view_map(filename):
  result = {
    "0": "DEFAULT"
  }
  if (os.path.isfile(filename)):
    fd = open(filename)
    linelist = fd.readlines()
    fd.close()
   
    for line in linelist:     
      itemlist = line.split()
      if (len(itemlist) != 2):
        continue
    
      key = itemlist[0].strip()
      value = itemlist[1].strip()
      if (result.has_key(value)):
        continue  
      else:
        result[value] = key              
    #for ends  
    return result   
  else:
    error = "[adns_parse_view_map]: %s is not a file!"     %(filename)
    ERROR(error)
    sys.exit()
     
 
def adns_file_tell(filename): 
  if (os.path.isfile(filename)):
    fd = open(filename, "a")
    seek = fd.tell()
    fd.close()   
    return seek
  else:
    error = "[adns_file_tell]: %s does not exist!"    %(filename)  
    ERROR(error)
    sys.exit()
 
 
#27-05-2015 19:21:15.794 [RET=0]: /home/adns/bin/adns_adm --show, 8ms    
def adns_check_adm_log(filename, seek, keyword, expect_ret):   
  result = {
    "success": 0,
    "failure": 0,
    "total": 0          
  }
  
  if (os.path.isfile(filename)):
    fd = open(filename)
    fd.seek(seek)
    linelist = fd.readlines()
    fd.close()
    
    pattern = '(?<=%s)(.*?)(?=%s)'                                           %('RET=', '\]')
    for line in linelist:
      if (line.find(keyword) == -1):
        continue 
      
      result["total"] += 1
      try:
        ret = int(re.search(pattern, line).group()) 
        if (ret != expect_ret):
          result["failure"] += 1            
          error = "[adns_check_adm_log]: line = %s, ret = %d, expect_ret = %d"   %(line[:-1], ret, expect_ret)
          ERROR(error)
           
        else:
          result["success"] += 1
      except Exception, err:
        error = "[adns_check_adm_log]: line = %s, %s!"                           %(line[:-1], str(err))
        ERROR(error)
        sys.exit()
    #for ends  
    info = "[adns_check_adm_log]: TOTAL = %d, SUCCESS = %d, PERCENT = %.2f%%, RET = %d"    %(result["total"], result["success"], result["success"]/1.0/result["total"]*100, expect_ret)
    SHOW(info)                
  else:
    error = "[adns_check_adm_log]: %s does not exist!"                           %(filename)  
    ERROR(error)
    sys.exit()
    

def adns_adm_show(key, expect_count, expect_percent):
  cmd = "/home/adns/bin/adns_adm --show"
  #INFO(cmd)
 
  success_flag = 0 
  output = os.popen(cmd)
  linelist = output.readlines()  
  for line in linelist[1:]:
    itemlist = line.split()
    if (len(itemlist) != 3):
      continue
  
    name = itemlist[0][:-1]
    if (name != key):
      continue
  
    count = int(itemlist[1])
    if (count != expect_count):
      error = "[adns_adm_show]: real_count = %d, expect_count = %d"                       %(count, expect_count)
      ERROR(error)
      break
      
    percent = float(itemlist[2])
    if (percent != expect_percent):
      error = "[adns_adm_show]: real_percent = %.2f, expect_count = %.2f%%"               %(percent, expect_percent)
      ERROR(error)
      break
  
    success_flag = 1  
    break          
  #for ends
  if (success_flag == 1):
    info = "[adns_adm_show]: MATCH SUCCESS, name = %s, count = %d, percent = %.2f%%"      %(key, expect_count, expect_percent)   
    SHOW(info)
  else:
    info = "[adns_adm_show]: MATCH FAILURE, name = %s"                                    %(key)
    SHOW(info) 
       
  
def adns_check_zone_threshold(adm_log, server_log, zone_max_num): 
  info = "\n\n----------------------------zone_max_num(%d)----------------------------"   %(zone_max_num) 
  SHOW(info, "magenta")
  
  cmd = "/home/adns/bin/adns_adm --clear"
  SHOW(cmd)
  os.system(cmd)
  
  #50% TEST
  info = "\n----------------------------50% TEST"
  SHOW(info, "yellow")
  seek = adns_file_tell(adm_log) 
  for i in range(zone_max_num/2):
    cmd = '/home/adns/bin/adns_adm -A --zone myexamplezone%d.org -r "ns1.myexamplezone1.org. mailMaster1.myexamplezone1.org. 1406084183 600 900 1209600 600" '    %(i)
    os.system(cmd)
  #for ends
  adns_check_adm_log(adm_log, seek, "/home/adns/bin/adns_adm -A ", 0)
  show_result = adns_adm_show("zone", zone_max_num/2, 50)
  
  #100% TEST
  info = "\n----------------------------100% TEST"
  SHOW(info, "yellow")
  seek = adns_file_tell(adm_log) 
  for i in range(zone_max_num/2, zone_max_num):
    cmd = '/home/adns/bin/adns_adm -A --zone myexamplezone%d.org -r "ns1.myexamplezone1.org. mailMaster1.myexamplezone1.org. 1406084183 600 900 1209600 600" '    %(i)
    os.system(cmd)
  #for ends 
  adns_check_adm_log(adm_log, seek, "/home/adns/bin/adns_adm -A ", 0) 
  show_result = adns_adm_show("zone", zone_max_num, 100)
  
  #overflow
  info = "\n----------------------------OVERFLOW TEST"
  SHOW(info, "yellow")
  seek = adns_file_tell(adm_log) 
  for i in range(zone_max_num, zone_max_num + 10):
    cmd = '/home/adns/bin/adns_adm -A --zone myexamplezone%d.org -r "ns1.myexamplezone1.org. mailMaster1.myexamplezone1.org. 1406084183 600 900 1209600 600" '    %(i)
    os.system(cmd)
  #for ends 
  adns_check_adm_log(adm_log, seek, "/home/adns/bin/adns_adm -A ", -199) 
  show_result = adns_adm_show("zone", zone_max_num, 100)
  

def adns_check_domain_threshold(adm_log, server_log, domain_max_num): 
  info = "\n\n----------------------------domain_max_num(%d)----------------------------"   %(domain_max_num) 
  SHOW(info, "magenta")
  
  cmd = "/home/adns/bin/adns_adm --clear"
  SHOW(cmd)
  os.system(cmd)
  
  section_max = 20
  info = "/home/adns/bin/adns_adm -A --zone(%d)"     %(section_max)
  SHOW(info)
  for i in range(section_max):
    cmd = '/home/adns/bin/adns_adm -A --zone myexamplezone%d.org -r "ns1.myexamplezone1.org. mailMaster1.myexamplezone1.org. 1406084183 600 900 1209600 600" '  %(i)
    os.system(cmd)
  
  #50% TEST
  info = "\n----------------------------50% TEST"
  SHOW(info, "yellow")
  seek = adns_file_tell(adm_log) 
  for i in range(domain_max_num/2):
    zone_index = random.randint(0, section_max - 1)  
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view DEFAULT -C IN -t A -T 600 -r "1.1.1.1" -w 1 '      %(zone_index, i, zone_index)
    os.system(cmd)
  #for ends
  adns_check_adm_log(adm_log, seek, "/home/adns/bin/adns_adm -a ", 0)
  show_result = adns_adm_show("domain", domain_max_num/2, 50)
  
  #100% TEST
  info = "\n----------------------------100% TEST"
  SHOW(info, "yellow")
  seek = adns_file_tell(adm_log) 
  for i in range(domain_max_num/2, domain_max_num):
    zone_index = random.randint(0, section_max - 1)  
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view DEFAULT -C IN -t A -T 600 -r "1.1.1.1" -w 1 '      %(zone_index, i, zone_index)
    os.system(cmd)
  #for ends
  adns_check_adm_log(adm_log, seek, "/home/adns/bin/adns_adm -a ", 0)
  show_result = adns_adm_show("domain", domain_max_num, 100)
  
  #overflow
  info = "\n----------------------------OVERFLOW TEST"
  SHOW(info, "yellow")
  seek = adns_file_tell(adm_log) 
  for i in range(domain_max_num, domain_max_num + 10):
    zone_index = random.randint(0, section_max - 1)  
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view DEFAULT -C IN -t A -T 600 -r "1.1.1.1" -w 1 '      %(zone_index, i, zone_index)
    os.system(cmd)
  #for ends 
  adns_check_adm_log(adm_log, seek, "/home/adns/bin/adns_adm -a ", -296) 
  show_result = adns_adm_show("domain", domain_max_num, 100)


def adns_check_domain_name_len_threshold(adm_log, server_log, name_len_type, domain_name_len_num):
  info = "\n\n----------------------------domain_len_%d_num(%d)----------------------------"     %(name_len_type, domain_name_len_num) 
  SHOW(info, "magenta")
    
  cmd = "/home/adns/bin/adns_adm --clear"
  SHOW(cmd)
  os.system(cmd)
  
  section_max = 20
  info = "/home/adns/bin/adns_adm -A --zone(%d)"     %(section_max)
  SHOW(info)
  for i in range(section_max):
    cmd = '/home/adns/bin/adns_adm -A --zone myexamplezone%d.org -r "ns1.myexamplezone1.org. mailMaster1.myexamplezone1.org. 1406084183 600 900 1209600 600" '  %(i)
    os.system(cmd)
    
  domain_name_prefix_map = {
    "32": "hello",                 #23
    "64": "helloworldhelloworld",  #38   
    "128": "helloworldhelloworldhelloworldhelloworldhelloworldhelloworld", #78
    "256": "helloworldhelloworld.helloworldhelloworldhelloworldhelloworldhelloworld.helloworldhelloworldhelloworldhelloworld.helloworldhelloworldhelloworld.helloworldhelloworldhelloworldhelloworld",  #198
  }
  index = str(name_len_type)
  name_key = "domain_len_%d"       %(name_len_type)
  domain_name_prefix = domain_name_prefix_map[index]
  
  #50% TEST
  info = "\n----------------------------50% TEST"
  SHOW(info, "yellow")
  seek = adns_file_tell(adm_log) 
  for i in range(domain_name_len_num/2):
    zone_index = random.randint(0, section_max - 1)  
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain %s%d.myexamplezone%d.org. --view DEFAULT -C IN -t A -T 600 -r "1.1.1.1" -w 1 '      %(zone_index, domain_name_prefix, i, zone_index)
    os.system(cmd)
  #for ends
  adns_check_adm_log(adm_log, seek, "/home/adns/bin/adns_adm -a ", 0)
  show_result = adns_adm_show(name_key, domain_name_len_num/2, 50)
  
  #100% TEST
  info = "\n----------------------------100% TEST"
  SHOW(info, "yellow")
  seek = adns_file_tell(adm_log) 
  for i in range(domain_name_len_num/2, domain_name_len_num):
    zone_index = random.randint(0, section_max - 1)  
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain %s%d.myexamplezone%d.org. --view DEFAULT -C IN -t A -T 600 -r "1.1.1.1" -w 1 '      %(zone_index, domain_name_prefix, i, zone_index)
    os.system(cmd)
  #for ends
  adns_check_adm_log(adm_log, seek, "/home/adns/bin/adns_adm -a ", 0)
  show_result = adns_adm_show(name_key, domain_name_len_num, 100)
  
  #overflow
  info = "\n----------------------------OVERFLOW TEST"
  SHOW(info, "yellow")
  seek = adns_file_tell(adm_log) 
  for i in range(domain_name_len_num, domain_name_len_num + 10):
    zone_index = random.randint(0, section_max - 1)  
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain %s%d.myexamplezone%d.org. --view DEFAULT -C IN -t A -T 600 -r "1.1.1.1" -w 1 '      %(zone_index, domain_name_prefix, i, zone_index)
    os.system(cmd)
  #for ends 
  adns_check_adm_log(adm_log, seek, "/home/adns/bin/adns_adm -a ", -296) 
  show_result = adns_adm_show(name_key, domain_name_len_num, 100)
      

def adns_check_record_threshold(adm_log, server_log, rr_max_num):
  info = "\n\n----------------------------rr_max_num(%d)----------------------------"     %(rr_max_num) 
  SHOW(info, "magenta")
    
  cmd = "/home/adns/bin/adns_adm --clear"
  SHOW(cmd)
  os.system(cmd)
  
  section_max = 20
  info = "/home/adns/bin/adns_adm -A --zone(%d)"     %(section_max)
  SHOW(info)
  for i in range(section_max):
    cmd = '/home/adns/bin/adns_adm -A --zone myexamplezone%d.org -r "ns1.myexamplezone1.org. mailMaster1.myexamplezone1.org. 1406084183 600 900 1209600 600" '  %(i)
    os.system(cmd)
  
  #50% TEST
  info = "\n----------------------------50% TEST"
  SHOW(info, "yellow")
  seek = adns_file_tell(adm_log) 
  for i in range(rr_max_num/2):
    zone_index = random.randint(0, section_max - 1) 
    rr_index_0 = random.randint(0, 255)
    rr_index_1 = random.randint(0, 255)
    rr_index_2 = random.randint(0, 255)
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view DEFAULT -C IN -t A -T 600 -r "1.%d.%d.%d" -w 1 '      %(zone_index, zone_index, zone_index, rr_index_2, rr_index_1, rr_index_0)
    os.system(cmd)
  #for ends
  adns_check_adm_log(adm_log, seek, "/home/adns/bin/adns_adm -a ", 0)
  show_result = adns_adm_show("rr", rr_max_num/2, 50)
  
  #100% TEST
  info = "\n----------------------------100% TEST"
  SHOW(info, "yellow")
  seek = adns_file_tell(adm_log) 
  for i in range(rr_max_num/2, rr_max_num):
    zone_index = random.randint(0, section_max - 1) 
    rr_index_0 = random.randint(0, 255)
    rr_index_1 = random.randint(0, 255)
    rr_index_2 = random.randint(0, 255)
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view DEFAULT -C IN -t A -T 600 -r "2.%d.%d.%d" -w 1 '      %(zone_index, zone_index, zone_index, rr_index_2, rr_index_1, rr_index_0)
    os.system(cmd)
  #for ends
  adns_check_adm_log(adm_log, seek, "/home/adns/bin/adns_adm -a ", 0)
  show_result = adns_adm_show("rr", rr_max_num, 100)
  
  #overflow
  info = "\n----------------------------OVERFLOW TEST"
  SHOW(info, "yellow")
  seek = adns_file_tell(adm_log) 
  for i in range(rr_max_num, rr_max_num + 10):
    zone_index = random.randint(0, section_max - 1) 
    rr_index_0 = random.randint(0, 255)
    rr_index_1 = random.randint(0, 255)
    rr_index_2 = random.randint(0, 255)
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view DEFAULT -C IN -t A -T 600 -r "3.%d.%d.%d" -w 1 '      %(zone_index, zone_index, zone_index, rr_index_2, rr_index_1, rr_index_0)
    os.system(cmd)
  #for ends 
  adns_check_adm_log(adm_log, seek, "/home/adns/bin/adns_adm -a ", -291) 
  show_result = adns_adm_show("rr", rr_max_num, 100)
  

def adns_check_record_rdata_ctl_threshold(adm_log, server_log, view_group_map, rdata_ctl_max_num):
  info = "\n\n----------------------------rdata_ctl_max_num(%d)----------------------------"     %(rdata_ctl_max_num) 
  SHOW(info, "magenta")
    
  cmd = "/home/adns/bin/adns_adm --clear"
  SHOW(cmd)
  os.system(cmd)
  
  view_max_num = len(view_group_map)
  section_max = rdata_ctl_max_num/5 + 30
  info = "/home/adns/bin/adns_adm -A --zone(%d)"     %(section_max)
  SHOW(info)
  for i in range(section_max):
    cmd = '/home/adns/bin/adns_adm -A --zone myexamplezone%d.org -r "ns1.myexamplezone1.org. mailMaster1.myexamplezone1.org. 1406084183 600 900 1209600 600" '  %(i)
    os.system(cmd)
  
  #50% TEST
  info = "\n----------------------------50% TEST"
  SHOW(info, "yellow")
  seek = adns_file_tell(adm_log) 
  for i in range(rdata_ctl_max_num/10):
    #zone_index = random.randint(0, section_max/3 - 1)
    zone_index = i 
    rr_index_0 = random.randint(0, 255)
    rr_index_1 = random.randint(0, 255)
    rr_index_2 = random.randint(0, 255)
    view_index = str(random.randint(1, view_max_num - 1))
    view_name = view_group_map[view_index]    
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view %s -C IN -t A -T 600 -r "1.%d.%d.%d" -w 1 '                                  %(zone_index, zone_index, zone_index, view_name, rr_index_2, rr_index_1, rr_index_0)
    os.system(cmd)
    
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view %s -C IN -t TXT -T 600 -r "v=spf%d include:spf.mxhichina.com -all"'          %(zone_index, zone_index, zone_index, view_name, i)
    os.system(cmd)
    
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view %s -C IN -t SRV -T 600 -r "1 100 443 sipdir%d.online.partner.lync.cn."'      %(zone_index, zone_index, zone_index, view_name, i)
    os.system(cmd)
    
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view %s -C IN -t AAAA -T 600 -r "2604:a880:%d:%d::15f:5001"'                      %(zone_index, zone_index, zone_index, view_name, rr_index_2, rr_index_1)
    os.system(cmd)
    
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view %s -C IN -t NS -T 600 -r "dns%d.hichina.com"'                                %(zone_index, zone_index, zone_index, view_name, i)
    os.system(cmd)
  #for ends
  adns_check_adm_log(adm_log, seek, "/home/adns/bin/adns_adm -a ", 0)
  show_result = adns_adm_show("rdata_ctl_num", rdata_ctl_max_num/2, 50)
  
  #100% TEST
  info = "\n----------------------------100% TEST"
  SHOW(info, "yellow")
  seek = adns_file_tell(adm_log) 
  for i in range(rdata_ctl_max_num/10, rdata_ctl_max_num/5):
    #zone_index = random.randint(0, section_max/3 - 1)
    zone_index = i
    rr_index_0 = random.randint(0, 255)
    rr_index_1 = random.randint(0, 255)
    rr_index_2 = random.randint(0, 255)
    view_index = str(random.randint(1, view_max_num - 1))
    view_name = view_group_map[view_index]   
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view %s -C IN -t A -T 600 -r "1.%d.%d.%d" -w 1 '                                  %(zone_index, zone_index, zone_index, view_name, rr_index_2, rr_index_1, rr_index_0)
    os.system(cmd)
    
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view %s -C IN -t TXT -T 600 -r "v=spf%d include:spf.mxhichina.com -all"'          %(zone_index, zone_index, zone_index, view_name, i)
    os.system(cmd)
    
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view %s -C IN -t SRV -T 600 -r "1 100 443 sipdir%d.online.partner.lync.cn."'      %(zone_index, zone_index, zone_index, view_name, i)
    os.system(cmd)
    
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view %s -C IN -t AAAA -T 600 -r "2604:a880:%d:%d::15f:5001"'                      %(zone_index, zone_index, zone_index, view_name, rr_index_2, rr_index_1)
    os.system(cmd)
    
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view %s -C IN -t NS -T 600 -r "dns%d.hichina.com"'                                %(zone_index, zone_index, zone_index, view_name, i)
    os.system(cmd)
  #for ends
  adns_check_adm_log(adm_log, seek, "/home/adns/bin/adns_adm -a ", 0)
  show_result = adns_adm_show("rdata_ctl_num", rdata_ctl_max_num, 100)
  
  #overflow
  info = "\n----------------------------OVERFLOW TEST"
  SHOW(info, "yellow")
  seek = adns_file_tell(adm_log) 
  for i in range(rdata_ctl_max_num/5, rdata_ctl_max_num/5 + 2):
    #zone_index = random.randint(0, section_max/3 - 1)
    zone_index = i
    rr_index_0 = random.randint(0, 255)
    rr_index_1 = random.randint(0, 255)
    rr_index_2 = random.randint(0, 255)
    view_index = str(random.randint(1, view_max_num - 1))
    view_name = view_group_map[view_index]   
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view %s -C IN -t A -T 600 -r "1.%d.%d.%d" -w 1 '                                  %(zone_index, zone_index, zone_index, view_name, rr_index_2, rr_index_1, rr_index_0)
    os.system(cmd)
    
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view %s -C IN -t TXT -T 600 -r "v=spf%d include:spf.mxhichina.com -all"'          %(zone_index, zone_index, zone_index, view_name, i)
    os.system(cmd)
    
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view %s -C IN -t SRV -T 600 -r "1 100 443 sipdir%d.online.partner.lync.cn."'      %(zone_index, zone_index, zone_index, view_name, i)
    os.system(cmd)
    
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view %s -C IN -t AAAA -T 600 -r "2604:a880:%d:%d::15f:5001"'                      %(zone_index, zone_index, zone_index, view_name, rr_index_2, rr_index_1)
    os.system(cmd)
    
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view %s -C IN -t NS -T 600 -r "dns%d.hichina.com"'                                %(zone_index, zone_index, zone_index, view_name, i)
    os.system(cmd)
  #for ends 
  adns_check_adm_log(adm_log, seek, "/home/adns/bin/adns_adm -a ", -293) 
  show_result = adns_adm_show("rdata_ctl_num", rdata_ctl_max_num, 100)


def adns_check_record_rrset_memory_threshold(adm_log, server_log, rrset_memory_max_num):
  info = "\n\n----------------------------rrset_memory_max_num(%d)----------------------------"     %(rrset_memory_max_num) 
  SHOW(info, "magenta")
    
  cmd = "/home/adns/bin/adns_adm --clear"
  SHOW(cmd)
  os.system(cmd)
  
  section_max = rrset_memory_max_num/5 + 30
  info = "/home/adns/bin/adns_adm -A --zone(%d)"     %(section_max)
  SHOW(info)
  for i in range(section_max):
    cmd = '/home/adns/bin/adns_adm -A --zone myexamplezone%d.org -r "ns1.myexamplezone1.org. mailMaster1.myexamplezone1.org. 1406084183 600 900 1209600 600" '  %(i)
    os.system(cmd)
  
  #50% TEST
  info = "\n----------------------------50% TEST"
  SHOW(info, "yellow")
  seek = adns_file_tell(adm_log) 
  for i in range(rrset_memory_max_num/10):
    rr_index_0 = random.randint(0, 255)
    rr_index_1 = random.randint(0, 255)
    rr_index_2 = random.randint(0, 255)  
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view DEFAULT -C IN -t A -T 600 -r "1.%d.%d.%d" -w 1 '                                  %(i, i, i, rr_index_2, rr_index_1, rr_index_0)
    os.system(cmd)
    
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view DEFAULT -C IN -t TXT -T 600 -r "v=spf%d include:spf.mxhichina.com -all"'          %(i, i, i, i)
    os.system(cmd)
    
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view DEFAULT -C IN -t SRV -T 600 -r "1 100 443 sipdir%d.online.partner.lync.cn."'      %(i, i, i, i)
    os.system(cmd)
    
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view DEFAULT -C IN -t AAAA -T 600 -r "2604:a880:%d:%d::15f:5001"'                      %(i, i, i, rr_index_2, rr_index_1)
    os.system(cmd)
    
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view DEFAULT -C IN -t NS -T 600 -r "dns%d.hichina.com"'                                %(i, i, i, i)
    os.system(cmd)
  #for ends
  adns_check_adm_log(adm_log, seek, "/home/adns/bin/adns_adm -a ", 0)
  show_result = adns_adm_show("rrset_memory_num", rrset_memory_max_num/2, 50)
  
  #100% TEST
  info = "\n----------------------------100% TEST"
  SHOW(info, "yellow")
  seek = adns_file_tell(adm_log) 
  for i in range(rrset_memory_max_num/10, rrset_memory_max_num/5):
    rr_index_0 = random.randint(0, 255)
    rr_index_1 = random.randint(0, 255)
    rr_index_2 = random.randint(0, 255)  
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view DEFAULT -C IN -t A -T 600 -r "1.%d.%d.%d" -w 1 '                                  %(i, i, i, rr_index_2, rr_index_1, rr_index_0)
    os.system(cmd)
    
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view DEFAULT -C IN -t TXT -T 600 -r "v=spf%d include:spf.mxhichina.com -all"'          %(i, i, i, i)
    os.system(cmd)
    
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view DEFAULT -C IN -t SRV -T 600 -r "1 100 443 sipdir%d.online.partner.lync.cn."'      %(i, i, i, i)
    os.system(cmd)
    
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view DEFAULT -C IN -t AAAA -T 600 -r "2604:a880:%d:%d::15f:5001"'                      %(i, i, i, rr_index_2, rr_index_1)
    os.system(cmd)
    
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view DEFAULT -C IN -t NS -T 600 -r "dns%d.hichina.com"'                                %(i, i, i, i)
    os.system(cmd)
  #for ends
  adns_check_adm_log(adm_log, seek, "/home/adns/bin/adns_adm -a ", 0)
  show_result = adns_adm_show("rrset_memory_num", rrset_memory_max_num, 100)
  
  #overflow
  info = "\n----------------------------OVERFLOW TEST"
  SHOW(info, "yellow")
  seek = adns_file_tell(adm_log) 
  for i in range(rrset_memory_max_num/5, rrset_memory_max_num/5 + 2):
    rr_index_0 = random.randint(0, 255)
    rr_index_1 = random.randint(0, 255)
    rr_index_2 = random.randint(0, 255)  
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view DEFAULT -C IN -t A -T 600 -r "1.%d.%d.%d" -w 1 '                                  %(i, i, i, rr_index_2, rr_index_1, rr_index_0)
    os.system(cmd)
    
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view DEFAULT -C IN -t TXT -T 600 -r "v=spf%d include:spf.mxhichina.com -all"'          %(i, i, i, i)
    os.system(cmd)
    
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view DEFAULT -C IN -t SRV -T 600 -r "1 100 443 sipdir%d.online.partner.lync.cn."'      %(i, i, i, i)
    os.system(cmd)
    
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view DEFAULT -C IN -t AAAA -T 600 -r "2604:a880:%d:%d::15f:5001"'                      %(i, i, i, rr_index_2, rr_index_1)
    os.system(cmd)
    
    cmd = '/home/adns/bin/adns_adm -a --zone myexamplezone%d.org. --domain www%d.myexamplezone%d.org. --view DEFAULT -C IN -t NS -T 600 -r "dns%d.hichina.com"'                                %(i, i, i, i)
    os.system(cmd)
  #for ends 
  adns_check_adm_log(adm_log, seek, "/home/adns/bin/adns_adm -a ", -295) 
  show_result = adns_adm_show("rrset_memory_num", rrset_memory_max_num, 100)
        

def adns_check_conf(conf_map, switch):
  adm_log = "/home/adns/var/log/adns_adm.log"
  server_log = "/home/adns/var/log/adns_server.log"
  if (switch["zone"] == True):
    zone_max_num = int(conf_map["zone_max_num"])
    adns_check_zone_threshold(adm_log, server_log, zone_max_num)

  if (switch["domain"] == True):
    domain_max_num = int(conf_map["domain_max_num"])
    conf_map["domain_len_32"] = int(conf_map["domain_len_32"])
    conf_map["domain_len_64"] = int(conf_map["domain_len_64"])
    conf_map["domain_len_128"] = int(conf_map["domain_len_128"])
    conf_map["domain_len_256"] = int(conf_map["domain_len_256"])
    
    if (conf_map["domain_len_32"] < domain_max_num) and (conf_map["domain_len_64"] < domain_max_num) and (conf_map["domain_len_128"] < domain_max_num) and (conf_map["domain_len_256"] < domain_max_num):
      #adns_check_domain_threshold(adm_log, server_log, domain_max_num)  
      pass
    else:        #domain_len_32
      error = "[adns_check_conf]: domain_len_x exceed domain_max_num = %d"        %(domain_max_num)
      ERROR(error) 

    adns_check_domain_name_len_threshold(adm_log, server_log, 32, conf_map["domain_len_32"])
    adns_check_domain_name_len_threshold(adm_log, server_log, 64, conf_map["domain_len_64"])
    adns_check_domain_name_len_threshold(adm_log, server_log, 128, conf_map["domain_len_128"])
    adns_check_domain_name_len_threshold(adm_log, server_log, 256, conf_map["domain_len_256"])
  
  if (switch["record"] == True):
    rr_max_num = int(conf_map["rr_max_num"])                                    #rr              1000
    conf_map["rdata_ctl_max_num"] = int(conf_map["rdata_ctl_max_num"])
    conf_map["rdata_ctl_max_num"] = int(conf_map["rdata_ctl_max_num"])          #view/rr         2000
    conf_map["rrset_memory_max_num"] = int(conf_map["rrset_memory_max_num"])    #rr              2000     
    view_group_map = adns_parse_view_map(conf_map["view_map"])  
      
    #adns_check_record_threshold(adm_log, server_log, rr_max_num)
    #adns_check_record_rdata_ctl_threshold(adm_log, server_log, view_group_map, conf_map["rdata_ctl_max_num"])     #domain/type/N-default
    adns_check_record_rrset_memory_threshold(adm_log, server_log, conf_map["rrset_memory_max_num"])               #domain/type
        

def adns_parse_conf(filename, conf_map):
  if (os.path.isfile(filename)):
    fd = open(filename)
    linelist = fd.readlines()
    fd.close()
   
    for line in linelist:
      if (line.find(";") != -1):
        continue
      
      itemlist = line.split("=")
      if (len(itemlist) != 2):
        continue
    
      key = itemlist[0].strip()
      value = itemlist[1].strip()
      if (conf_map.has_key(key)):
        conf_map[key] = value  
      else:
        continue      
    #for ends     
  else:
    error = "[adns_parse_conf]: %s is not a file!"     %(filename)
    ERROR(error)
    sys.exit()


def adns_print_conf(conf_map):
  info = "\n\n----------------ADNS CONF PRINT----------------"
  SHOW(info)
  
  for key in sorted(conf_map):
    msg = "[%-20s]: %s"       %(key, conf_map[key])
    SHOW(msg, "yellow")
    
    
if __name__ == "__main__":      
  usage = "USAGE: %prog [option]"
  
  parser = OptionParser(usage)
  parser.add_option("--conf", dest="adns_conf", default="/home/adns/etc/adns.conf", help="set adns conf")
  parser.add_option("--zone", dest="zone_check", action="store_true", default=True, help="check zone threshold")
  parser.add_option("--domain", dest="domain_check", action="store_true", default=False, help="check domain threshold")
  parser.add_option("--record", dest="record_check", action="store_true", default=False, help="check record threshold")
    
  (options, args) = parser.parse_args()
  switch = {       
    "zone": options.zone_check,
    "domain": options.domain_check,
    "record": options.record_check        
  }
    
  conf_map = {
    "view_map": None,
    "ipfile_path": None,
    
    "zone_max_num": None,
    "domain_max_num": None,
    "domain_len_32": None,
    "domain_len_64": None,
    "domain_len_128": None,
    "domain_len_256": None,
    
    "view_max_num": None, 
    "rr_max_num": None,        
    "rdata_ctl_max_num": None,   
    "rrset_memory_max_num": None, 
  }  
  
  CLEAN_LOG()
  
  filename = options.adns_conf
  adns_parse_conf(filename, conf_map)
  adns_print_conf(conf_map)
  
  adns_check_conf(conf_map, switch)
  
  
    
