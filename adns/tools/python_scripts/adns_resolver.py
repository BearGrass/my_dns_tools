#!/usr/bin/python
# -*- coding: utf-8 -*-


import os
import sys
import random
import socket
import struct

import dns.resolver
import dns.message
import clientsubnetoption as CSO
from adns_log import LOG
from email import errors


class RESOLVER():
    subnet_map = {
        "0": ["default", None, None]
    }
    log = None
    old_version_vip = None
    new_version_vip = None
    
    
    def __init__(self, view_map_file, ip_range_map_file, old_version_vip, new_version_vip):
        try:
            self.log = LOG()
            self.old_version_vip = old_version_vip
            self.new_version_vip = new_version_vip
            
            #view_map_file: CN_CERNET 1
            fd = open(view_map_file)
            linelist = fd.readlines()
            fd.close()

            for line in linelist:
                viewlist = line.split()
                if (len(viewlist) != 2):
                    raise 
                
                view_name = viewlist[0]
                view_id = viewlist[1]
                if (self.subnet_map.has_key(view_id)):
                    raise
                else:
                    self.subnet_map[view_id] = [view_name, None, None]                                                             
            #for view_map ends
                      
            #ip_range_map_file: 20447232 20971519 4
            fd = open(ip_range_map_file)
            linelist = fd.readlines()
            fd.close()
                       
            for line in linelist:
                itemlist = line.split()
                if (len(itemlist) != 3):
                    raise 
                
                view_id = itemlist[2]
                if (self.subnet_map[view_id][1] != None):
                    continue
                
                start_ip = int(itemlist[0])
                end_ip = int(itemlist[1])
                subnet_ip = random.randint(start_ip, end_ip)                
                ip_addr = socket.inet_ntoa(struct.pack("!L", subnet_ip))   #socket.inet_ntoa(struct.pack("!L", 17040384)) = "1.4.4.0"
                self.subnet_map[view_id][1] = subnet_ip
                self.subnet_map[view_id][2] = ip_addr  
            #for ip_range_map ends   
                
            self.print_subnet_map()
        except Exception, err:
            error = "[__init__]: "
  
  
    def print_subnet_map(self):
        msg = "-------------------Print Subnet Result-------------------"
        self.log.SHOW(msg) 
        
        for view_id in sorted(self.subnet_map):
            view_name = self.subnet_map[view_id][0]
            subnet_ip_addr = self.subnet_map[view_id][2]
            
            info = "[%s]: view_name = %-12s, select_subnet_ip = %s"      %(view_id, view_name, subnet_ip_addr)
            self.log.INFO(info)
        #for ends
        
    
    def record_type_to_value(self, type):
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
           #"ANY": 255
        }
        if (map.has_key(type)):
            return map[type]
        else:
            return None


    def comparse_result(self, old, new, err_str):
        rcode_error_flag = 0
        for key in old:
          if (key == "RCODE"):
              if (old[key] != new[key]):
                  rcode_error_flag = 1
              else:
                  continue
          else:
             old_type_map = old[key]
             new_type_map = new[key]

             for type in old_type_map:
                old_value = old_type_map[type]
                new_value = new_type_map[type]
                if (old_value != new_value):
                    if (rcode_error_flag == 0):
                        err_str.append('RCODE_OK_CONTENT_ERROR')
                        return -2
                    else:
                        err_str.append('RCODE_ERROR_CONTENT_ERROR')
                        return -3
        #for ends
        if (rcode_error_flag == 0):
            return 0              #SUCCESS
        else:
            err_str.append('RCODE_ERROR_CONTENT_OK')
            return -1


    def query_edns(self, domain, wild_domain_flag):
        try:
            for view_id in sorted(self.subnet_map):
                subnet_ip = self.subnet_map[view_id][1]
                subnet_ip_addr = self.subnet_map[view_id][2]

                for type in ['SOA', 'A', 'AAAA', 'CNAME', 'NS', 'MX', 'PTR', 'TXT', 'SRV']:
                    for i in range(3):
                        query_port = random.randint(10000, 50000)
                        old_version_result = self.query_edns_type(self.old_version_vip, query_port, subnet_ip, domain, type)
                        old_info = "[OLD_%d]: %s, %s, [%s] %s, wild = %d, rcode = %s, ans = %s, auth = %s, addt = %s"  \
                                %(i, domain, type, view_id, subnet_ip_addr, wild_domain_flag, str(old_version_result["RCODE"]), str(old_version_result["ANSWER"]), str(old_version_result["AUTHORITY"]), str(old_version_result["ADDITIONAL"]))
                        if (old_version_result["RCODE"] != None):
                            break

                    for i in range(3):
                        query_port = random.randint(10000, 50000)
                        new_version_result = self.query_edns_type(self.new_version_vip, query_port, subnet_ip, domain, type)
                        new_info = "[NEW_%d]: %s, %s, [%s] %s wild = %d, rcode = %s, ans = %s, auth = %s, addt = %s"  \
                                %(i, domain, type, view_id, subnet_ip_addr, wild_domain_flag, str(new_version_result["RCODE"]), str(new_version_result["ANSWER"]), str(new_version_result["AUTHORITY"]), str(old_version_result["ADDITIONAL"]))
                        if (new_version_result["RCODE"] != None):
                            break

                    err_str = []
                    ret = self.comparse_result(old_version_result, new_version_result, err_str)
                    if (ret != 0):
                        self.log.RECORD(old_info)
                        self.log.RECORD(new_info)
                        self.log.RECORD("")
                        error = "[diff]: domain = %s, %s, %s, %s" %(domain, type, self.subnet_map[view_id][0], err_str[0])
                        self.log.INFO(error)
        except  Exception, err:
            error = "[query_edns]: domain = %s, %s" %(domain, str(err))
            self.log.ERROR(error)
            sys.exit()


    def query_edns_type(self, query_server, query_port, subnet_ip, domain, type):
        try:
            args = {
                "family": 1,
                "mask": 32,
            }

            result = {
                "RCODE": None,
                "ANSWER": {
                    "SOA": [],
                    "A": [],
                    "AAAA": [],
                    "CNAME": [],
                    "NS": [],
                    "MX": [],
                    "PTR": [],
                    "TXT": [],
                    "SRV": []
                },
                "AUTHORITY": {
                    "SOA": [],
                    "A": [],
                    "AAAA": [],
                    "CNAME": [],
                    "NS": [],
                    "MX": [],
                    "PTR": [],
                    "TXT": [],
                    "SRV": []
                },
                "ADDITIONAL": {
                    "SOA": [],
                    "A": [],
                    "AAAA": [],
                    "CNAME": [],
                    "NS": [],
                    "MX": [],
                    "PTR": [],
                    "TXT": [],
                    "SRV": []
                }
            }

            cso = CSO.ClientSubnetOption(args["family"], subnet_ip, args["mask"], option=CSO.ASSIGNED_OPTION_CODE)
            message = dns.message.make_query(domain, type)
            message.use_edns(options=[cso])

            r = dns.query.udp(message, query_server, timeout = 2)
            rc = dns.rcode.from_flags(r.flags, r.ednsflags)
            result["RCODE"] = rc

            #ANSWER SECTION
            answer_map = result["ANSWER"]
            for response in r.answer:
                for item in response.items:
                    if (item.rdtype == self.record_type_to_value('A')):
                        ip = item.address          #'1.1.1.1'
                        answer_map["A"].append(ip)
                    elif (item.rdtype == self.record_type_to_value('AAAA')):
                        ip = item.address          #'ff03:0:0:0:0:0:0:c1' 
                        answer_map["AAAA"].append(ip)
                    elif (item.rdtype == self.record_type_to_value('CNAME')):
                        name = item.to_text()      #'9kuai9.tk'
                        answer_map["CNAME"].append(name)
                    elif (item.rdtype == self.record_type_to_value('NS')):
                        name = item.to_text()      #'dns13.hichina.com.'
                        answer_map["NS"].append(name)
                    elif (item.rdtype == self.record_type_to_value('MX')):
                        name = item.to_text()      #'10 mxw.mxhichina.com.'
                        answer_map["MX"].append(name)   
                    elif (item.rdtype == self.record_type_to_value('PTR')):
                        name = item.to_text()      #'cashier-60-1.zue'
                        answer_map["PTR"].append(name)   
                    elif (item.rdtype == self.record_type_to_value('TXT')):
                        name = item.to_text()      #"v=spf1 include:spf.mxhichina.com -all"
                        answer_map["TXT"].append(name)
                    elif (item.rdtype == self.record_type_to_value('SRV')):
                        name = item.to_text()      #'100 1 5061 sipfed.online.lync.com.'
                        answer_map["SRV"].append(name)
                    elif (item.rdtype == self.record_type_to_value('SOA')):
                        name = item.to_text()      #'dada18.cn. 600 IN SOA dns21.hichina.com. hostmaster.hichina.com. 1 3600 1200 3600 600'
                        answer_map["SOA"].append(name)
                    else:
                        continue                    
            #for ends
            
            #AUTHORITY SECTION
            authority_map = result["AUTHORITY"]
            for response in r.authority:                             
                for item in response.items:          
                    if (item.rdtype == self.record_type_to_value('A')):
                        ip = item.address          #'1.1.1.1'
                        authority_map["A"].append(ip)
                    elif (item.rdtype == self.record_type_to_value('AAAA')):
                        ip = item.address          #'ff03:0:0:0:0:0:0:c1' 
                        authority_map["AAAA"].append(ip)
                    elif (item.rdtype == self.record_type_to_value('CNAME')):
                        name = item.to_text()      #'9kuai9.tk'
                        authority_map["CNAME"].append(name)
                    elif (item.rdtype == self.record_type_to_value('NS')):
                        name = item.to_text()      #'dns13.hichina.com.'
                        authority_map["NS"].append(name)                        
                    elif (item.rdtype == self.record_type_to_value('MX')):
                        name = item.to_text()      #'10 mxw.mxhichina.com.'
                        authority_map["MX"].append(name)   
                    elif (item.rdtype == self.record_type_to_value('PTR')):
                        name = item.to_text()      #'cashier-60-1.zue'
                        authority_map["PTR"].append(name)   
                    elif (item.rdtype == self.record_type_to_value('TXT')):
                        name = item.to_text()      #"v=spf1 include:spf.mxhichina.com -all"
                        authority_map["TXT"].append(name)
                    elif (item.rdtype == self.record_type_to_value('SRV')):
                        name = item.to_text()      #'100 1 5061 sipfed.online.lync.com.'
                        authority_map["SRV"].append(name)
                    elif (item.rdtype == self.record_type_to_value('SOA')):
                        name = item.to_text()      #'dada18.cn. 600 IN SOA dns21.hichina.com. hostmaster.hichina.com. 1 3600 1200 3600 600'
                        answer_map["SOA"].append(name)
                    else:
                        continue  

            #ADDITIONAL SECTION
            additional_map = result["ADDITIONAL"]
            for response in r.additional:                             
                for item in response.items:          
                    if (item.rdtype == self.record_type_to_value('A')):
                        ip = item.address          #'1.1.1.1'
                        additional_map["A"].append(ip)
                    elif (item.rdtype == self.record_type_to_value('AAAA')):
                        ip = item.address          #'ff03:0:0:0:0:0:0:c1' 
                        additional_map["AAAA"].append(ip)
                    elif (item.rdtype == self.record_type_to_value('CNAME')):
                        name = item.to_text()      #'9kuai9.tk'
                        additional_map["CNAME"].append(name)
                    elif (item.rdtype == self.record_type_to_value('NS')):
                        name = item.to_text()      #'dns13.hichina.com.'
                        additional_map["NS"].append(name)                        
                    elif (item.rdtype == self.record_type_to_value('MX')):
                        name = item.to_text()      #'10 mxw.mxhichina.com.'
                        additional_map["MX"].append(name)   
                    elif (item.rdtype == self.record_type_to_value('PTR')):
                        name = item.to_text()      #'cashier-60-1.zue'
                        additional_map["PTR"].append(name)   
                    elif (item.rdtype == self.record_type_to_value('TXT')):
                        name = item.to_text()      #"v=spf1 include:spf.mxhichina.com -all"
                        additional_map["TXT"].append(name)
                    elif (item.rdtype == self.record_type_to_value('SRV')):
                        name = item.to_text()      #'100 1 5061 sipfed.online.lync.com.'
                        additional_map["SRV"].append(name)
                    elif (item.rdtype == self.record_type_to_value('SOA')):
                        name = item.to_text()      #'dada18.cn. 600 IN SOA dns21.hichina.com. hostmaster.hichina.com. 1 3600 1200 3600 600'
                        additional_map["SOA"].append(name)
                    else:
                        continue

            #ends
            for type in ['SOA', 'A', 'AAAA', 'CNAME', 'NS', 'MX', 'PTR', 'TXT', 'SRV']:
               answer_map = result["ANSWER"]
               answer_map[type] = ", ".join(sorted(answer_map[type]))
               
               authority_map = result["AUTHORITY"]
               authority_map[type] = ", ".join(sorted(authority_map[type]))
               
               additional_map = result["ADDITIONAL"]
               additional_map[type] = ", ".join(sorted(additional_map[type]))                                                                
            return result                                                                                        
        except Exception, err:
            error = "[query_edns_A]: domain = %s, %s"     %(domain, str(err) )
            self.log.ERROR(error)
            return result
   
   
    def get_subnet_ip_by_view_name(self, view_name):
        result = {
            "subnet_ip": None,
            "subnet_ip_addr": None          
        }   
        for view_id in self.subnet_map:
            itemlist = self.subnet_map[view_id]
            if (view_name != itemlist[0]):
                continue
            result["subnet_ip"] = itemlist[1]
            result["subnet_ip_addr"] = itemlist[2]
            return result
   
        
    def get_dig_rcode(self, vip_server, domain, type, view_name):
        try:
            subnet_result = self.get_subnet_ip_by_view_name(view_name)
                           
            for i in range(3):
                query_port = random.randint(10000, 60000)                      
                dig_result = self.query_edns_type(vip_server, query_port, subnet_result["subnet_ip"], domain, type)
                info = "[get_dig_rcode_%d]: domain = %s, type = %s, subnet_ip(%s) = %s, rcode = %s!"       %(i, domain, type, view_name, subnet_result["subnet_ip_addr"], str(dig_result["RCODE"]))
                self.log.RECORD(info)
                if (dig_result["RCODE"] != None):
                    return dig_result["RCODE"] 
            #for ends 
            return -2                                           
        except  Exception, err:
            error = "[get_dig_rcode]: domain = %s, %s"     %(domain, str(err))
            self.log.ERROR(error)
            sys.exit()


