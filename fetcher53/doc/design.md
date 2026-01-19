# EDNS
default buffer size is 1232 which is same with cloudflare public DNS, google DNS and
114 use 512.

# Truncate message
When serialized message size is bigger than 1232, tc bit will be set in header, and
answer, auth, additional section will be cleared. Google DNS has same implementation.
But bind will try to answer more data.  

# Reserved top level zone(TODO)
- example //as a normal top level zone

- test    //ns set to localhost, return nxdomaon for subdomain
- invalid  //ns set to localhost, return nxdomaon for subdomain
- localhost//ns set to localhost, return 127.0.0.1/::1 for subdomain a/aaaa

# Locally served zones 
Return nxdomain for domain under the following zone
10.IN-ADDR.ARPA      
16.172.IN-ADDR.ARPA  
17.172.IN-ADDR.ARPA  
18.172.IN-ADDR.ARPA  
19.172.IN-ADDR.ARPA  
20.172.IN-ADDR.ARPA  
21.172.IN-ADDR.ARPA  
22.172.IN-ADDR.ARPA  
23.172.IN-ADDR.ARPA  
24.172.IN-ADDR.ARPA  
25.172.IN-ADDR.ARPA  
26.172.IN-ADDR.ARPA  
27.172.IN-ADDR.ARPA  
28.172.IN-ADDR.ARPA  
29.172.IN-ADDR.ARPA  
30.172.IN-ADDR.ARPA  
31.172.IN-ADDR.ARPA  
168.192.IN-ADDR.ARPA 
0.IN-ADDR.ARPA                
127.IN-ADDR.ARPA   
254.169.IN-ADDR.ARPA         
2.0.192.IN-ADDR.ARPA         
100.51.198.IN-ADDR.ARPA      
113.0.203.IN-ADDR.ARPA       
255.255.255.255.IN-ADDR.ARPA
0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.IP6.ARPA 
1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.IP6.ARPA
D.F.IP6.ARPA 
8.E.F.IP6.ARPA 
9.E.F.IP6.ARPA 
A.E.F.IP6.ARPA 
B.E.F.IP6.ARPA
8.B.D.0.1.0.0.2.IP6.ARPA

# use local root zone(TODO)
use root zone file to replace prime query to root server
refresh interval == soa TTL or one day

# Serving Stale Data(TODO)
use 30 secs as ttl
