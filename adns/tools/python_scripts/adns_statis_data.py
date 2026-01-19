#!/usr/bin/python
# -*- coding: utf-8 -*-


import os,sys,re,time
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


def adns_print_base_statis(zone_map, domain_map, record_map):
  info = "\n\n----------------DOMAIN BASE STATISTICS----------------"
  SHOW(info, "magenta")
  
  zone_total_num = zone_map["total"]
  domain_total_num = domain_map["total"]
  record_total_num = record_map["total"]
  
  info = "ZONE NUMBER: %d"     %(zone_total_num)
  SHOW(info, "yellow") 

  info = "DOMAIN NUMBER: %d"   %(domain_total_num)
  SHOW(info, "yellow") 
  
  info = "RECORD NUMBER: %d"   %(record_total_num)
  SHOW(info, "yellow")     


def adns_print_record_statis(domain_map, record_map):
  info = "\n\n----------------DOMAIN RECORD STATISTICS----------------"
  SHOW(info, "magenta")
  
  support_type_map = {
    "A": 0, 
    "AAAA": 0, 
    "CNAME": 0, 
    "NS": 0, 
    "MX": 0, 
    "PTR": 0, 
    "TXT": 0, 
    "SRV": 0 
  }
  
  #init result{}
  result = {}
  for type in support_type_map:
     key = "domain_record_%s_num_1"                %(type)
     result[key] = 0
     
     key = "domain_record_%s_num_1_between_5"      %(type)
     result[key] = 0
     
     key = "domain_record_%s_num_5_between_10"     %(type)
     result[key] = 0
     
     key = "domain_record_%s_num_10_between_20"    %(type)
     result[key] = 0
     
     key = "domain_record_%s_num_gt_20"            %(type)
     result[key] = 0     
  
  #statis result{}          
  for domain in record_map:
    if (domain == "total"):
      continue
  
    type_map = record_map[domain]
    for type in type_map:
      rr_num = 0
              
      view_map = type_map[type]
      for view in view_map:
        if (view_map[view] > rr_num):
          rr_num = view_map[view]
      #for view_map
         
      if (rr_num == 1):
        key = "domain_record_%s_num_1"                %(type)
        result[key] += 1
      elif (rr_num <= 5):
        key = "domain_record_%s_num_1_between_5"      %(type)  
        result[key] += 1
      elif (rr_num <= 10):
        key = "domain_record_%s_num_5_between_10"     %(type)  
        result[key] += 1
      elif (rr_num <= 20):
        key = "domain_record_%s_num_10_between_20"    %(type)
        result[key] += 1
      else:
        key = "domain_record_%s_num_gt_20"            %(type)  
        result[key] += 1  
         
      support_type_map[type] += 1  
    #for type ends
  #for domain ends
  
  total_domain_num = domain_map["total"]
  format_flag = 0  
  for item in sorted(result):        
    name = item
    count = result[item]
    type = item.split("_")[2]
    
    if (support_type_map[type] != 0):
      percent = result[item] / 1.0 / support_type_map[type] * 100
      msg = "[%-37s]: %10d, percent = %.2f%%"         %(item, count, percent)
    else:
      msg = "[%-37s]: %10d, percent = -%%"            %(item, count)   
    SHOW(msg, "yellow")
    
    format_flag += 1
    format_flag %= 5
    if (format_flag == 0):
      print ""                    
  #for ends


def adns_print_view_statis(view_map, domain_map):
  info = "\n\n----------------DOMAIN VIEW STATISTICS----------------"
  SHOW(info, "magenta")
  
  result = {
    "domain_use_single_view_with_default_num": 0, 
    "domain_use_single_view_without_default_num": 0,   
    "domain_use_muti_views_with_default_num": 0, 
    "domain_use_muti_views_without_default_num": 0     
  }   
  for domain in view_map: 
    item_map = view_map[domain]
    if (len(item_map) == 1):
      if (item_map.has_key("default")):
        result["domain_use_single_view_with_default_num"] += 1
      else:
        result["domain_use_single_view_without_default_num"] += 1    
    else:
      if (item_map.has_key("default")):
        result["domain_use_muti_views_with_default_num"] += 1
      else:
        result["domain_use_muti_views_without_default_num"] += 1
  #for ends
   
  total_domain_num = domain_map["total"]  
  for item in sorted(result):
    name = item
    count = result[item]
    percent = result[item] / 1.0 / total_domain_num * 100
    msg = "[%-42s]: %10d, percent = %.2f%%"   %(item, count, percent)
    SHOW(msg, "yellow")
  #for ends
  
    
def adns_print_length_statis(length_map, domain_map):
  info = "\n\n----------------DOMAIN LENGHT STATISTICS----------------"
  SHOW(info, "magenta")
  
  total_domain_num = domain_map["total"]
  for item in sorted(length_map):
    name = item
    count = length_map[item]
    percent = length_map[item] / 1.0 / total_domain_num * 100
    msg = "[%-33s]: %10d, percent = %.2f%%"   %(item, count, percent)
    SHOW(msg, "yellow")


def adns_print_label_statis(label_map, domain_map):
  info = "\n\n----------------DOMAIN LABEL STATISTICS----------------"
  SHOW(info, "magenta")
  
  total_domain_num = domain_map["total"]
  for item in sorted(label_map):
    name = item
    count = label_map[item]
    percent = label_map[item] / 1.0 / total_domain_num * 100
    msg = "[%-33s]: %10d, percent = %.2f%%"   %(item, count, percent)
    SHOW(msg, "yellow")


def adns_print_result(switch, result):
  zone_map = result["zone"]
  domain_map = result["domain"] 
  record_map = result["record"]
  length_map = result["length"]
  label_map = result["label"]
  view_map = result["view"]
  
  #result["zone"]/result["domain"]/result["record"]
  adns_print_base_statis(zone_map, domain_map, record_map)
  
  #result["record"]
  adns_print_record_statis(domain_map, record_map)

  #result["view"]
  if (switch["view"] == True):
    adns_print_view_statis(view_map, domain_map)
         
  #result["length"]
  if (switch["length"] == True):
    adns_print_length_statis(length_map, domain_map)
        
  #result["label"]             
  if (switch["label"] == True):
    adns_print_label_statis(label_map, domain_map)
    

def adns_record_domain_length(filename, length_map, domain): 
  name_length = len(domain)
  if (name_length < 32):
    length_map["domain_name_length_0_between_32"] += 1
  elif (name_length < 64):
    length_map["domain_name_length_32_between_64"] += 1
  elif (name_length < 128):
    length_map["domain_name_length_64_between_128"] += 1
  else:
    length_map["domain_name_length_gt_128"] += 1  
    msg = "[adns_record_domain_length]: File = %s, domain = %s, name_length = %d"   %(filename, domain, name_length)
    ERROR(msg)
    

def adns_record_domain_label(filename, label_map, domain):                  
  name_label = len(domain.split(".")) - 1
  if (name_label < 3):
    label_map["domain_name_label_0_between_3"] += 1
  elif (name_label < 6):
    label_map["domain_name_label_3_between_6"] += 1
  elif (name_label < 8):
    label_map["domain_name_label_6_between_8"] += 1
  elif (name_label < 10):
    label_map["domain_name_label_8_between_10"] += 1
  else:
    label_map["domain_name_label_gt_10"] += 1  
    msg = "[adns_record_domain_label]: File = %s, domain = %s, name_label = %d"     %(filename, domain, name_label)
    ERROR(msg)
    

def adns_record_domain_view(filename, view_map, domain, view):
  if (view_map.has_key(domain)):
    if (view_map[domain].has_key(view)):
      view_map[domain][view] += 1
    else:
      view_map[domain][view] = 1
  else:
    view_map[domain] = {}
    view_map[domain][view] = 1    
  
    
# A iauto360.cn. 3600 dns31.hichina.com. hostmaster.hichina.com. 2015012914 3600 1200 3600 360
# a iauto360.cn. iauto360.cn. default IN NS 86400 dns31.hichina.com.
# a iauto360.cn. iauto360.cn. default IN NS 86400 dns32.hichina.com. 
# a iauto360.cn. dl.mt.iauto360.cn. default IN A 600 58.67.203.8 1 
# a iauto360.cn. test-h5.edaijia.iauto360.cn. default IN CNAME 3600 dyn-ip.iauto360.cn. 
# a iauto360.cn. test-service.iauto360.cn. default IN CNAME 3600 dyn-ip.iauto360.cn. 
# a iauto360.cn. tss.iauto360.cn. default IN A 600 58.67.203.8 1 
# a iauto360.cn. share.h5.app.iauto360.cn. default IN A 600 58.67.203.8 1 
def adns_analyse_file(filename, switch, result):  
  fd = open(filename)
  linelist = fd.readlines()
  fd.close()
  
  zone_map = result["zone"]
  domain_map = result["domain"] 
  record_map = result["record"]
  length_map = result["length"]
  label_map = result["label"]
  view_map = result["view"]
  for line in linelist:
    itemlist = line.split()
    if (len(itemlist) < 6):
      continue
    else:
      opcode = itemlist[0]
      if (opcode != "a"):
        continue
      else:
        zone = itemlist[1]     #iauto360.cn
        domain = itemlist[2]   #dl.mt.iauto360.cn.
        view = itemlist[3]     #default
        type = itemlist[5]     #NS/CNAME/A
        
        #result["zone"]
        if (zone_map.has_key(zone)):
          zone_map[zone] += 1
        else:
          zone_map[zone] = 1
          zone_map["total"] += 1
        
        #result["domain"]
        if (domain_map.has_key(domain)):
          domain_map[domain] += 1
        else:
          domain_map[domain] = 1
          domain_map["total"] += 1
                 
        #result["record"]
        record_map["total"] += 1
        if (record_map.has_key(domain)):
          if (record_map[domain].has_key(type)):
            if (record_map[domain][type].has_key(view)):
              record_map[domain][type][view] += 1  
            else:
              record_map[domain][type][view] = 1  
          else:
            record_map[domain][type] = {}
            record_map[domain][type][view] = 1
        else:
          record_map[domain] = {}         
          record_map[domain][type] = {}
          record_map[domain][type][view] = 1
        
        #result["view"]             
        if (switch["view"] == True):
          adns_record_domain_view(filename, view_map, domain, view)
          
        if (domain_map[domain] > 1):
          continue
        
        #result["length"]
        if (switch["length"] == True):
          adns_record_domain_length(filename, length_map, domain)
        
        #result["label"]             
        if (switch["label"] == True):
          adns_record_domain_label(filename, label_map, domain)
        
                   
def adns_analyse_path(root_dir, start_dir, end_dir, switch, result):  
  #ROOT DIR     
  if os.path.isdir(root_dir):
    list = os.listdir(root_dir)
    list.sort(lambda x,y:cmp(int(x.split("_")[0]), int(y.split("_")[0])))
  else:
    error = "[adns_analyse]: root_dir %s is not a dir!"     %(root_dir)
    ERROR(error)
    sys.exit()

  #START DIR-->END DIR 
  if (start_dir == None):
    start_flag = 1
  else:
    start_flag = 0 
  
  end_flag = 0      
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
    msg = "\n[adns_analyse_path]: path = %s"   %(filepath)
    SHOW(msg)
    
    if os.path.isdir(filepath):                    #/home/hejun.hj/20150304_realdata/adns_db_file/0        
        sublist = os.listdir(filepath)
        sublist.sort(lambda x,y:cmp(int(x.split("_")[0]), int(y.split("_")[0])))
        
        for line in sublist:          
          filename = os.path.join(filepath, line)  #/home/hejun.hj/20150304_realdata/adns_db_file/0/1.file
          info = "[adns_analyse_path]: filename = %s"   %(filename)
          INFO(info) 

          adns_analyse_file(filename, switch, result)  
    else:
      filename = ".".join(line.split(".")[:-1])
      error = "[adns_analyse_path]: Can not be here, file = %s"    %(filename)
      ERROR(error)
      sys.exit()
  #for ends   
        
        
if __name__ == "__main__":      
  usage = "USAGE: %prog [option]"
  
  parser = OptionParser(usage)
  parser.add_option("-r", "--root_dir", dest="root_dir", default="online/", help="set the root directory")
  parser.add_option("-s", "--start_dir", dest="start_dir", help="set the start directory")
  parser.add_option("-e", "--end_dir", dest="end_dir", help="set the end directory")

  parser.add_option("--length", dest="length_show", action="store_true", default=False, help="show length statistics")
  parser.add_option("--label", dest="label_show", action="store_true", default=False, help="show lable statistics")
  parser.add_option("--view", dest="view_show", action="store_true", default=True, help="show view statistics")
    
  (options, args) = parser.parse_args()
   
  root_dir = options.root_dir         
  start_dir = options.start_dir
  end_dir = options.end_dir
  switch = {
    "length": options.length_show,
    "label": options.label_show,
    "view":  options.view_show        
  }
  
  result = {
    "zone": {"total": 0},
    "domain": {"total": 0},    
    "record": {"total": 0},
    
    "length": {
      "domain_name_length_0_between_32": 0,
      "domain_name_length_32_between_64": 0,
      "domain_name_length_64_between_128": 0,
      "domain_name_length_gt_128": 0           
    },
    "label": {
      "domain_name_label_0_between_3": 0,
      "domain_name_label_3_between_6": 0,
      "domain_name_label_6_between_8": 0,
      "domain_name_label_8_between_10": 0,
      "domain_name_label_gt_10": 0          
    },
    "view": {},        
  }
  
  CLEAN_LOG()
  adns_analyse_path(root_dir, start_dir, end_dir, switch, result) 
  adns_print_result(switch, result)
 
 
 
    
    
