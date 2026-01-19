# DNS Mega 测试流程
## 测试包含如下项目，顺序不限
```
* 特殊域名测试，测试用例在 src/test/testdomain.sh
* 单元测试，测试用例在 src/test/testcase.c .
  主要测试函数的健壮性，覆盖主流程中所有的数据处理函数；
* 流量回放测试，目前以 dnstest05.tbc
  为测试机，主要测试所有 dnsmega 流程的健壮性（包括 vpc 流量）；
* testcenter 压力测试，压力测试，主要测试 dnsmega 的极限数据。
```

## 测试具体操作
### 特殊域名测试
```
sh src/test/testdomain.sh
```
### 单元测试
1、编译 dnsmegatest.ko 模块
```
cd dnsmega
make
ls src/test/dnsmegatest.ko
```
2、进行测试
```
sudo insmod src/test/dnsmegatest.ko
dmesg
```
3、dmesg 显示都 success 后即测试通过，如下：
```
[2666075.937970] [Testcase 1] Function get_node test result is success
[2666075.937973] [Testcase 2] Function update_node test result is
success
[2666075.937975] [Testcase 3] Function update_node test result is
success
[2666075.937977] [Testcase 4] Function put_node test result is success
...
```

### 流量回放测试
* 经典网络
**1、抓包**
登录到一台 ldns 上去，执行命令：
```
tcpdump -ni any udp and port 53 and dst ${本机IP} -nn -s0 -w dns.pcap
```
**2、修改包的二层-三层头**
```
tcpprep -p --pcap=dns.pcap --cachefile=test_cache.pcap #生成缓存文件
tcprewrite --srcipmap=10.0.0.0/8:${发包机IP}
--dstipmap=${抓包机器的IP}:${收包机IP}
--enet-smac=00:00:00:00:00:00,${发包机Mac}
--enet-dmac=00:00:00:00:00:00,${发包及网关Mac} --infile=dns.pcap
--outfile=output.pcap --skipbroadcast --cachefile=test_cache.pcap
--dlt=enet --fixcsum
```
**3、发包测试**
```
sudo tcpreplay -l ${循环次数} -p ${qps} --intf1=bond0 ddos.pcap
```
**4、持续观察**
```
python /home/mogu.lwp/dnsmega/script/dns_mega_counters.py
{"MSG": [{"request_out": 498032, "request_hit": 498032, "dns_drop": 0,
"passthrough": 9550, "mega_error": 0, "request_in": 498032}],
"collection_flag": 0, "error_info": ""}
[* 注意观察 error 和 drop 值]
cat /proc/dnsmega/counters
cat /proc/dnsmega/stats
```
**5、修改参数测试**
在流量回放加压的基础上需要进行一些参数的修改来压测一些特殊情况
5.1、观察大量队列链表操作
```
echo 1 > /proc/dnsmega/barely_trusted_time
echo 1 > /proc/dnsmega/expired_time
```
5.2、观察非正常域名请求丢包情况
```
echo 0 > /proc/dnsmega/max_req_waitlist_num
```

* vpc 网络
1、接入 vpc 流量
登录 vpc 的 vm
```
ssh 10.101.165.173
zcgo2vm i-dns-9 或者 zcgo2vm i-dns-8
```
2、发 dns 请求
以上俩 vm 到 dnstest05.tbc 是可通的，dnstest05.tbc 发起了 anycast
ip 为 10.101.242.5
```
# 手动生成一些 dns query
dig @10.101.242.5 www.alipay.com
```
PS: VM 相关的问题可以请教之初或者仙侠帮忙搞

### Testcenter 压力测试
1、登录 TC
```
远程桌面登录 10.137.59.12 ，账号找大本申请，密码 Ali-b2
```
2、部署 mega
```
ssh 10.137.59.22 #tc 跳板机
ssh 10.65.254.246 -lroot  #测试服务器 密码是 root
```
3、TC 发包
4、观察验证、数据统计
