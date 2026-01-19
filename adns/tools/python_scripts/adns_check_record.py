#!/usr/bin/python
# -*- coding: utf-8 -*-


import os,sys,re,time
import random
import threading
import dns.resolver
import dns.message
import termcolor
import socket
import struct
import clientsubnetoption as CSO
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

    
def RECORD(buf):
  filename = "logs/query.log" 
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

  query_log = logpath + "query.log"
  if os.path.isfile(query_log):   
    os.remove(query_log)


def adns_record_type_to_value(type = "A"):
  map = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "ANY": 255       
  }
  
  if (map.has_key(type)):
    return map[type]
  else:
    return None


def adns_query_edns_A(domain, rr_expect_map, port, subnet_ip, longest_match_rr_map, type="A"):
  try:
    args = {
      "family": 1,
      "mask": 32,           
    }  
    cso = CSO.ClientSubnetOption(args["family"], subnet_ip, args["mask"], option=CSO.ASSIGNED_OPTION_CODE)
    message = dns.message.make_query(domain, type)
    message.use_edns(options=[cso])
    
    r = dns.query.udp(message, "192.168.6.6", source_port = port, timeout = 2) 
    rc = dns.rcode.from_flags(r.flags, r.ednsflags)
    if (rc != 0):
      error = "[adns_query_edns_A]: domain = %s, rcode = %d"   %(domain, rc) 
      ERROR(error) 
      return -1   
    
    valid_data_flag = 0          
    for response in r.answer:                               
      for item in response.items:          
        if (item.rdtype == adns_record_type_to_value(type)): 
          ip = item.address
          buf = "[adns_query_edns_A]: domain = %s, dig_result = %s!"    %(domain, ip)
          RECORD(buf)
          
          if (rr_expect_map.has_key(ip)):
            rr_expect_map[ip] += 1
            valid_data_flag = 1  
          else:
            error = "[adns_query_edns_A]: domain = %s, dig_result = %s, expect_result = %s, longest_match_expect_result = %s!"   %(domain, ip, ",".join(rr_expect_map.keys()), longest_match_rr_map)  
            ERROR(error)
            #sys.exit()
        else:
          pass
    #for ends
    if (valid_data_flag == 0):
      error = "[adns_query_edns_A]: domain = %s, expect_result = %s, longest_match_expect_result = %s!"   %(domain, ",".join(rr_expect_map.keys()), longest_match_rr_map)  
      ERROR(error)
    return 0                                                                                                      
  except Exception, err:
    error = "[adns_query_edns_A]: domain = %s, error = NXDOMAIN, %s"   %(domain, str(err)) 
    ERROR(error) 
    return -1


def adns_query_edns_CNAME(domain, rr_expect_map, subnet_ip, longest_match_rr_map, type="CNAME"):
  try:
    args = {
      "family": 1,
      "mask": 32,           
    }  
    cso = CSO.ClientSubnetOption(args["family"], subnet_ip, args["mask"], option=CSO.ASSIGNED_OPTION_CODE)
    message = dns.message.make_query(domain, type)
    message.use_edns(options=[cso])
    
    r = dns.query.udp(message, "192.168.6.6", timeout = 2) 
    rc = dns.rcode.from_flags(r.flags, r.ednsflags)
    if (rc != 0):
      error = "[adns_query_edns_CNAME]: domain = %s, rcode = %d"   %(domain, rc) 
      ERROR(error) 
      return -1 
  
    for response in r.answer:             
      for item in response.items:
        if (item.rdtype == adns_record_type_to_value(type)):      
          name =  item.to_text()
          buf = "[adns_query_edns_CNAME]: domain = %s, dig_result = %s!"    %(domain, name)
          RECORD(buf)
          
          if (rr_expect_map.has_key(name)):
            rr_expect_map[name] += 1  
          else:
            error = "[adns_query_edns_CNAME]: domain = %s, dig_result = %s, expect_result = %s, longest_match_expect_result = %s!"   %(domain, name, ",".join(rr_expect_map.keys()), longest_match_rr_map)  
            ERROR(error)
            #sys.exit()
        else:
          pass
    #for ends
    return 0                                                                                                        
  except Exception, err:
    error = "[adns_query_edns_CNAME]: domain = %s, error = NXDOMAIN, %s"   %(domain, str(err)) 
    ERROR(error) 
    return -1
    #sys.exit()
    

def adns_query_A(domain, rr_expect_map, port, type="A"):
  try:
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['192.168.6.6']
    A = resolver.query(domain, type, source_port = port)        #<dns.resolver.Answer object at 0x16e6890>
    for response in A.response.answer:      #(list) [<DNS www.baidu.com. IN CNAME RRset>, <DNS www.a.shifen.com. IN A RRset>]
      for item in response.items:           #[<DNS IN CNAME rdata: www.a.shifen.com.>]  [<DNS IN A rdata: 115.239.210.27>, <DNS IN A rdata: 115.239.211.112>]
        if (item.rdtype == adns_record_type_to_value(type)):      #A record
          ip = item.address
          buf = "[adns_query_A]: domain = %s, dig_result = %s!"    %(domain, ip)
          RECORD(buf)
          
          if (rr_expect_map.has_key(ip)):
            rr_expect_map[ip] += 1  
          else:
            error = "[adns_query_A]: domain = %s, dig_result = %s, expect_result = %s!"   %(domain, ip, ",".join(rr_expect_map.keys()))  
            ERROR(error)
            #sys.exit()
        else:
          pass
    #for ends
    return 0                                                                                                      
  except Exception, err:
    error = "[adns_query_A]: domain = %s, error = NXDOMAIN, %s"   %(domain, str(err)) 
    ERROR(error) 
    return -1
    #sys.exit()


def adns_query_CNAME(domain, rr_expect_map, type="CNAME"):
  try:
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['192.168.6.6']  
    CNAME = resolver.query(domain, type)    
    for response in CNAME.response.answer:     
      for item in response.items:
        if (item.rdtype == adns_record_type_to_value(type)):      
          name =  item.to_text()
          buf = "[adns_query_CNAME]: domain = %s, dig_result = %s!"    %(domain, name)
          RECORD(buf)
          
          if (rr_expect_map.has_key(name)):
            rr_expect_map[name] += 1  
          else:
            error = "[adns_query_CNAME]: domain = %s, dig_result = %s, expect_result = %s!"   %(domain, name, ",".join(rr_expect_map.keys()))  
            ERROR(error)
            #sys.exit()
        else:
          pass
    #for ends
    return 0                                                                                                        
  except Exception, err:
    error = "[adns_query_CNAME]: domain = %s, error = NXDOMAIN, %s"   %(domain, str(err)) 
    ERROR(error) 
    return -1
    #sys.exit()


def adns_print_statis(filename, result):
  msg = "-------------------ADNS Statis Result: %s -------------------"    %(filename)
  SHOW(msg) 
  
  zone_total_count = len(result)
  zone_count = 0
  domain_count = 0
  rr_count = 0
  rr_success_count = 0
  
  progress_map = {
    "20": None,
    "30": None,
    "40": None,
    "50": None,
    "60": None,
    "70": None,
    "80": None,
    "90": None,
    "95": None,
    "99": None                
  }
  for zone in sorted(result):
    zone_count += 1
    
    progress = zone_count / 1.0 / zone_total_count * 100
    if (progress < 10):
      pass
    elif (progress < 20):
      if (progress_map["20"] == None):          
        progress_map["20"] = 1
        info = "[adns_print_statis]: progress = %.2f%%, 10%%~20%%!"     %(progress)
        SHOW(info, "yellow")        
    elif (progress < 30):
      if (progress_map["30"] == None):          
        progress_map["30"] = 1  
        info = "[adns_print_statis]: progress = %.2f%%, 20%%~30%%!"     %(progress)
        SHOW(info, "yellow")
    elif (progress < 40):
      if (progress_map["40"] == None):          
        progress_map["40"] = 1
        info = "[adns_print_statis]: progress = %.2f%%, 30%%~40%%!"     %(progress)
        SHOW(info, "yellow")
    elif (progress < 50):
      if (progress_map["50"] == None):          
        progress_map["50"] = 1
        info = "[adns_print_statis]: progress = %.2f%%, 40%%~50%%!"     %(progress)
        SHOW(info, "yellow")
    elif (progress < 60):
      if (progress_map["60"] == None):          
        progress_map["60"] = 1
        info = "[adns_print_statis]: progress = %.2f%%, 50%%~60%%!"     %(progress)
        SHOW(info, "yellow")
    elif (progress < 70):
      if (progress_map["70"] == None):          
        progress_map["70"] = 1
        info = "[adns_print_statis]: progress = %.2f%%, 60%%~70%%!"     %(progress)
        SHOW(info, "yellow")
    elif (progress < 80):
      if (progress_map["80"] == None):          
        progress_map["80"] = 1
        info = "[adns_print_statis]: progress = %.2f%%, 70%%~80%%!"     %(progress)
        SHOW(info, "yellow")
    elif (progress < 90):
      if (progress_map["90"] == None):          
        progress_map["90"] = 1  
        info = "[adns_print_statis]: progress = %.2f%%, 80%%~90%%!"     %(progress)
        SHOW(info, "yellow")
    elif (progress < 95):
      if (progress_map["95"] == None):          
        progress_map["95"] = 1
        info = "[adns_print_statis]: progress = %.2f%%, 90%%~95%%!"     %(progress)
        SHOW(info, "yellow")
    elif (progress < 99):
      if (progress_map["99"] == None):          
        progress_map["99"] = 1
        info = "[adns_print_statis]: progress = %.2f%%!"              %(progress)
        SHOW(info, "yellow")
        
    domain_map = result[zone]
    for domain in sorted(domain_map):
      domain_count += 1
      
      view_map = domain_map[domain]
      if (view_map.has_key("OVERSEA")):
        type_map = view_map["OVERSEA"]  
      else:        
        type_map = view_map["default"]
      
      for type in sorted(type_map):
        if (type == "NS"):
          continue
        rr_map = type_map[type]
        
        for rr in sorted(rr_map):
          rr_count += 1 
          if (rr_map[rr] != 0):
            rr_success_count += 1          
  #for ends
  msg = "----zone_count = %d"    %(zone_count)
  SHOW(msg)
  
  msg = "----domain_count = %d"  %(domain_count)
  SHOW(msg)
  
  msg = "----rr_count = %d, success = %d, rate = %.2f%%\n\n"      %(rr_count, rr_success_count, rr_success_count / 1.0 / rr_count * 100)
  SHOW(msg) 


def adns_query(filename, result, view_name, subnet_ip):
  msg = "-------------------ADNS Query Statis: %s-------------------"     %(filename)
  SHOW(msg) 
  
  for zone in sorted(result):    
    domain_map = result[zone]
    threadlist = []
    zonelist = zone.split(".") 
    
    for domain in sorted(domain_map):
      #The longest match
      long_match_flag = 0
      long_match_wildcard_flag = 0
      domainlist = domain.split(".")
      longest_match_len = len(domainlist) - len(zonelist)
      if (longest_match_len > 1):    
        for i in range(1, longest_match_len):
          longest_match_zone = ".".join(domainlist[i:])
          longest_match_wildcard_zone = "*." + longest_match_zone
          if (result.has_key(longest_match_zone)):
            error = "[adns_query]: Exist Longest Match, zone = %s, domain = %s, longest_match_zone = %s"    %(zone, domain, longest_match_zone)
            ERROR(error)
            long_match_flag = 1
          else:
            continue
      
      if (long_match_flag == 1):
        longest_match_domain_map = result[longest_match_zone]
        if (longest_match_domain_map.has_key(domain)):                         #www.bymz.com.cn
          longest_match_view_map = longest_match_domain_map[domain]
          longest_match_domain = domain
          error = "[adns_query]: Match longest domain Success, zone = %s, domain = %s, longest_match_zone = %s"    %(zone, domain, longest_match_zone)
          ERROR(error)
        elif (longest_match_domain_map.has_key(longest_match_wildcard_zone)):  #*.bymz.com.cn
          longest_match_view_map = longest_match_domain_map[longest_match_wildcard_zone]
          longest_match_domain = longest_match_wildcard_zone
          long_match_wildcard_flag = 1
          error = "[adns_query]: Match wildcard Success, zone = %s, domain = %s, longest_match_zone = %s"          %(zone, domain, longest_match_zone)
          ERROR(error)
        else:
          error = "[adns_query]: NO Match Data, zone = %s, domain = %s, longest_match_zone = %s"                   %(zone, domain, longest_match_zone)
          ERROR(error)
          continue  
      
        if (longest_match_view_map.has_key(view_name)):
          longest_match_type_map = longest_match_view_map[view_name]
          view = view_name 
        else:        
          longest_match_type_map = longest_match_view_map["default"]
          view = "default" 
                                
      view_map = domain_map[domain]        
      if (view_map.has_key(view_name)):
        type_map = view_map[view_name]
        view = view_name 
      else:        
        type_map = view_map["default"]
        view = "default"
      
      for type in sorted(type_map):          
        rr_map = type_map[type]
        
        info = "[adns_query]: zone = %s, domain = %s, view = %s, type = %s, expect = %s"   %(zone, domain, view, type, ",".join(rr_map.keys()))        
        #INFO(info)
        
        longest_match_rr_map = "None"
        try:
          if (long_match_flag == 1):
            if (longest_match_type_map.has_key(type)):
              longest_match_rr_map = ",".join(longest_match_type_map[type].keys())   # A VS CNAME
            else:
              longest_match_rr_map = ",".join(longest_match_type_map["CNAME"].keys()) 
          else:
            longest_match_rr_map = "None"
        except:
          longest_match_rr_map = "None"
                                  
        if (type == "CNAME"):            
          if (len(rr_map) != 1):
            error = "[adns_query]: domain = %s, type = CNAME, rr_count != 1!"   %(domain)
            ERROR(error)
            sys.exit()
          else:            
            adns_query_edns_CNAME(domain, rr_map, subnet_ip, longest_match_rr_map)
        elif (type == "A"):
          if (type_map.has_key("NS")):      #A and NS exist at the same time
            if (zone == domain):            #return A record(Answer Section) 
              info = "[adns_query]: Zone Record, zone = %s, domain = %s, view = %s, A and NS exist at the same time"   %(zone, domain, view)
              #SHOW(info, "yellow")
            else:                           #return NS record(Authority Section), pass temporarily by shengyan 2015/04/30
              info = "[adns_query]: Non-Zone Record, zone = %s, domain = %s, view = %s, A and NS exist at the same time"   %(zone, domain, view)
              #SHOW(info, "yellow")
              for rr in rr_map:
                rr_map[rr] = 1
              continue
          
          times = len(rr_map)  
          source_port = random.randint(10000, 60000) 
          if (times == 1):           
            ret = adns_query_edns_A(domain, rr_map, source_port, subnet_ip, longest_match_rr_map)
            if (ret != 0):
              source_port = random.randint(10000, 60000)   
              for i in range(3):
                if (adns_query_edns_A(domain, rr_map, source_port, subnet_ip, longest_match_rr_map) == 0):
                  error = "[adns_query]: domain = %s, retry SUCCESS!"   %(domain)
                  ERROR(error)  
                  break                  
          else:
            for i in range(3*times):
              adns_query_edns_A(domain, rr_map, source_port, subnet_ip, longest_match_rr_map)
                          
          for rr in rr_map:
            if (rr_map[rr] == 0):
              error = "[adns_query]: zone = %s, domain = %s, rr = %s, type = A, len(rr_map) = %d"   %(zone, domain, rr, times)
              ERROR(error)    
        else:
          continue
    #for ends (domain)
  #for ends(zone)


#view_map_file
#CN_CERNET 1
#CN_CHINANET 2

#ip_map_file
#16777472 16778239 2
#16778240 16779263 5
def adns_generate_subnet(view_dir, view_name):
  view_map_file = view_dir + "/view_name_id.map"
  ip_map_file = view_dir + "/ip_range.map"
  
  if (os.path.isfile(view_map_file) == False):
    error = "[adns_generate_subnet]: view_map_file %s not existed!"    %(view_map_file)
    ERROR(error)
    sys.exit()
  
  if (os.path.isfile(ip_map_file) == False):
    error = "[adns_generate_subnet]: ip_map_file %s not existed!"      %(ip_map_file)
    ERROR(error)
    sys.exit()
  
  view_id = None
  if (view_name == "default"):
    view_id = 0
  else:
    fd = open(view_map_file)
    linelist = fd.readlines()
    fd.close()
    
    for line in linelist:
      itemlist = line.split()
      if (len(itemlist) != 2):
        continue 
  
      if (itemlist[0] == view_name):
        view_id = itemlist[1]
        break
    #for ends    
  if (view_id == None):
    error = "[adns_generate_subnet]: view_name %s not existed!"      %(view_name)
    ERROR(error)
    sys.exit()    
  
  subnet_ip = None
  fd = open(ip_map_file)
  linelist = fd.readlines()
  fd.close() 
  
  for line in linelist:
    itemlist = line.split()
    if (len(itemlist) != 3):
      continue
  
    if (itemlist[2] == view_id):
      start_ip = int(itemlist[0])
      end_ip = int(itemlist[1])
      subnet_ip = random.randint(start_ip, end_ip)         #struct.unpack('!L', socket.inet_aton("1.4.4.0"))[0] = 17040384
      ip = socket.inet_ntoa(struct.pack("!L", subnet_ip))  #socket.inet_ntoa(struct.pack("!L", 17040384))
      info = "[adns_generate_subnet]: view_name = %s, view_id = %s, ip = %s, subnet_ip = %d!"           %(view_name, view_id, ip, subnet_ip)
      SHOW(info)
      break
  #for ends
  if (subnet_ip == None):
    error = "[adns_generate_subnet]: Can not find matched subnet ip, view_name = %s, view_id = %s!"     %(view_name, view_id)
    ERROR(error)
    sys.exit()  
  return subnet_ip

 
#(SOA)   A iauto360.cn. 3600 dns31157.hichina.com. hostmaster.hichina.com. 2015012914 3600 1200 3600 360
#(A)     a iauto360.cn. gis-api.iauto360.cn. default IN A 600 58.67.203.8 1
#(CNAME) a iauto360.cn. test-mt.iauto360.cn. default IN CNAME 600 dyn-ip.iauto360.cn.

#(NS)    a iauto360.cn. iauto360.cn. default IN NS 86400 dns31.hichina.com.
#(MX)    a sunhometj.com. sunhometj.com. default IN MX 600 10 mx02.mail.alibaba.com.
#(TXT)   a qianchen123.com. qianchen123.com. default IN TXT 600 e5bd12a4-1e9e-4727-b858-abf68ddc9c00-1415929907931 
def adns_anaylse_file(filename, result, view_name="OVERSEA"):
  fd = open(filename)
  linelist = fd.readlines()
  fd.close()
  
  for line in linelist:
    itemlist = line.split()
    if (len(itemlist) < 6):
      continue
    else:
      opcode = itemlist[0]
      if (opcode == "A"):
        zone = itemlist[1].lower()    #iauto360.cn.
        if (result.has_key(zone) == False):
          result[zone] = {}
        continue
      
      elif (opcode == "a"):
        zone = itemlist[1].lower()     #iauto360.cn.
        domain = itemlist[2].lower()   #gis-api.iauto360.cn.
        view = itemlist[3]     #default
        if (view != "default") and (view != view_name):
          error = "[adns_anaylse_file]: view != default or oversea, line = %s!"   %(line[:-1])
          #ERROR(error)
          continue
        type = itemlist[5]
        if (type == "A"):
          record = itemlist[7].lower()
        elif (type == "CNAME"):
          record = itemlist[7].lower()
        elif (type == "NS"):
          record = itemlist[7].lower()
        else:
          continue
        
        #check zone
        if (result.has_key(zone) == False):
          if (zone == "my3w.com."):
            continue
          error = "[adns_anaylse_file]: Zone does not exist when add record, line = %s!"   %(line[:-1])
          ERROR(error)
          #sys.exit()
          continue
        
        #handle domain
        if (result[zone].has_key(domain) == False):
          result[zone][domain] = {}
        
        #handle view
        domain_map = result[zone][domain]
        if (domain_map.has_key(view) == False):
          domain_map[view] = {}
                
        #handle record 
        view_map = domain_map[view]
        if (view_map.has_key(type) == False):
          view_map[type] = {}  

        rr_map = view_map[type]  
        if (rr_map.has_key(record) == False):
          rr_map[record] = 0
      else:
        continue

       
def adns_analyse(root_dir, start_dir, end_dir, view_dir, view_name): 
  result = {}
    
  if os.path.isdir(root_dir):
    list = os.listdir(root_dir)
    list.sort(lambda x,y:cmp(int(x.split("_")[0]), int(y.split("_")[0])))
  else:
    error = "[adns_analyse]: root_dir %s is not a dir!"     %(root_dir)
    ERROR(error)
    sys.exit()

  #Make sure start to end
  subnet_ip = adns_generate_subnet(view_dir, view_name)
  
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
    msg = "\n[adns_analyse]: path = %s"   %(filepath)
    SHOW(msg)
    
    if os.path.isdir(filepath):                    #/home/hejun.hj/20150304_realdata/adns_db_file/0        
        sublist = os.listdir(filepath)
        sublist.sort(lambda x,y:cmp(int(x.split("_")[0]), int(y.split("_")[0])))
        
        for line in sublist:          
          filename = os.path.join(filepath, line)  #/home/hejun.hj/20150304_realdata/adns_db_file/0/a.file
          info = "[adns_analyse]: filename = %s"   %(filename)
          INFO(info)
          adns_anaylse_file(filename, result, view_name)    
    else:
      file = ".".join(line.split(".")[:-1])
      error = "[adns_analyse]: Can not be here, file = %s"    %(file)
      ERROR(error)
      sys.exit()
  #for ends  
  adns_query("ALL", result, view_name, subnet_ip)  
  adns_print_statis("ALL", result)
         
        
if __name__ == "__main__":
  usage = "usage: %prog [option]"
  parser = OptionParser(usage)
  parser.add_option("-r", "--root_dir", dest="root_dir", default="online/", help="set the root directory")
  parser.add_option("-s", "--start_dir", dest="start_dir", help="set the start directory")
  parser.add_option("-e", "--end_dir", dest="end_dir", help="set the end directory")
  
  parser.add_option("--view_dir", dest="view_dir", default="view_data/", help="set the view directory")  
  parser.add_option("--view_name", dest="view_name", default="OVERSEA", help="set the view name")
    
  (options, args) = parser.parse_args()
   
  root_dir = options.root_dir         
  start_dir = options.start_dir
  end_dir = options.end_dir  
  view_dir = options.view_dir
  view_name = options.view_name
         
  CLEAN_LOG()  
  adns_analyse(root_dir, start_dir, end_dir, view_dir, view_name) 



    
