## 配置文件路径
```
/proc/dnsmega/
```

## 配置文件释义
```
on                          暂时废弃
cache_on                    缓存启用开关
clear_counters              清空计数器，输入1表示清空
max_cache_num               最大 cache 节点数量
dns_port                    自定义 DNS 端口，默认 53
barely_trusted_time         缓存绝对信任时间
expired_time                缓存过期时间
max_req_waitlist-num        缓存节点等待应答列表长度
forward_timeout_sec         转发到后端等待应答的超时时间
forward_ratelimit_qps       转发到后端的限速 qps
forward_ratelimit_sec       转发到后端的限速统计间隔
cache_clean_interval_ms     缓存过期清理检查间隔
cache_clean_bulk_num        缓存过期清理每次清理节点数
ip_ratelimit_qps            单 IP 限速 qps
ip_ratelimit_on             单 IP 限速开关
ip_rec_ratelimit_on         单 IP 递归请求限速开关
ip_rec_ratelimit_qps        单 IP 递归请求限速 qps
```

## 系统统计值
```
version                     DNS Mega 版本号
counters                    DNS Mega 系统计数器
stats                       DNS Mega 实时状态统计
```

## 计数器原则
* info 级别
accept 系列       透传包统计
request 系列      缓存现状 qps 统计使用

* error 级别
drop 系列         丢包统计
error 系列        系统内部函数调用故障

当某些申请内存失败时，记录为一次系统 error，如果 error 一定引起
drop，则额外增加到一个 drop 计数器中。



## 详细计数器释义
```
accept_in_l3                IP 层收包透传
accept_in_l4                UDP 层收包透传
accept_in_l7                DNS 层收包透传
accept_linearize_in         非线性入包透传

accept_out_l3               IP 层发包透传
accept_out_l4               UDP 层发包透传
accept_out_l7               DNS 层发包透传
accept_linearize_out        非线性出包透传
accept_loopback_out         回环口出包透传
accept_nosupport            不支持的 DNS 报文透传

drop_ip_ratelimit           单 IP 限速丢包
drop_ip_rec_ratelimit       单 IP 递归请求限速丢包
drop_pac_incomplete         报文不完整丢包
drop_pac_oversize           请求报文过大丢包
drop_parse_error            DNS 畸形报文丢包
drop_waitlist_full          cache 中等待队列溢出丢包
drop_forward_ratelimit      转发后端限速丢包
drop_waitlist_full          cache 等待应答列表溢出丢包
drop_nomem_request          申请 request 空间失败丢包
drop_genpac_error           生成回包错误丢包


request_in                  DNS 请求收到的包
request_out                 DNS 请求应答的包
request_hit                 cache 命中的包
request_hold                cache 暂存的包
request_prefetch            cache 发出预取请求

cache_expired               缓存过期数量

error_nomem_request         申请 request 空间失败
error_nomem_skb             copy skb 申请空间失败
error_big_append            skb 扩容过大报错
error_update_rt             更新路由失败
error_cow_head              预留 MAC 头部失败
error_response_no_cache     后端应答未命中缓存
error_nomem_node            申请 cache 节点失败
error_nomem_node_val        申请 cache 节点value失败
error_nomem_node_key        申请 cache 节点key失败

fwd_logic_response          mega 应答的报文数
fwd_real_response           后端 BIND 应答的报文数
fwd_real_timeout            后端 BIND 应答超时
fwd_queries                 转发到后端的请求

```

## 状态统计
```
cache_with_answer_num        cache 中有内容的节点数量
cache_without_answer_num     cache 中内容待填充的节点数量
wait_request_num             等待队列中的请求
```
