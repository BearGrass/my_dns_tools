# don't cache no soa nxdomain, no error empty response
# auth return refused, resolver return server fail
# invalid cname response 
return first answer
- CNAME+A => CNAME
- A+CNAME => A
# invalid ns response in auth
www.example.com. IN A
below.www.example.com. 300 IN NS ns.below.www.example.com.
ns.below.www.example.com. 300 IN A 10.53.0.3
# no aa bit response
# stub/forward zone 
# private network address provide empty zone 
# soa record is parent
sub zone return parent zone soa
# pre-fetch
# mx/srv 对应的glue (223,114,1,8都只应答answer）
aliyun.com mx
srv record
# glue has cname, ignore this glue
# opcode know ==> format error
  opcode reserved ==> not implement
# edns client subnet
# return non-zero ttl
# tc = 1 and question is empty is valid when return from auth
# serve-stale
# negative ttl = min(soa minim + soa ttl)
# rdata round robin
