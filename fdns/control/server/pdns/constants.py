# coding=utf-8
BASE_PAGE_SIZE = 15

HEADERS = {
    "Content-type": "application/x-www-form-urlencoded",
    "Accept": "text/plain"
}

#AGENT端口
AGENT_PORT = 9999

#server类型
SERVER_TYPE_FWD = "forwarder"
SERVER_TYPE_REDIS = "redis"
SERVER_TYPE_CDN = "cdn"

PDNS_SYNC_STAUS_INIT = 0

# 以下是时间对应的秒数
TIME_1_SEC = 1
TIME_1_MIN = 1 * 60
TIME_5_MIN = 5 * 60
TIME_1_HOUR = 1 * 60 * 60

# REQUEST
REQUEST_EN_CH_MAP = [
    {'name_en': "req_in", 'name_cn': "总请求个数"},
    {'name_en': "fwd_req", 'name_cn': "转发请求个数"},
    {'name_en': "req_hit", 'name_cn': "请求命中个数"},
    {'name_en': "fwd_logic_rep", 'name_cn': "后端DNS返回逻辑响应个数"},
    {'name_en': "fwd_real_rep", 'name_cn': "后端DNS返回真实响应个数"},
    {'name_en': "fwd_timeout", 'name_cn': "超时个数"},
    {'name_en': "req_top_in", 'name_cn': "热点域名请求个数"},
    {'name_en': "req_top_hit", 'name_cn': "热点域名命中个数"},
    {'name_en': "servfail", 'name_cn': "响应servFail数"},
]
# drop
DROP_EN_CH_MAP = [
    {'name_en': "dns_parse", 'name_cn': "DNS解析丢弃包数"},
    {'name_en': "jmalloc_fail", 'name_cn': "jmalloc内存分配失败丢弃包数"},
    {'name_en': "mp_get_fail", 'name_cn': "mempool内存分配失败丢弃包数"},
    {'name_en': "resp_fwd_none", 'name_cn': "非后端节点返回的响应丢弃包数"},
    {'name_en': "same_req", 'name_cn': "相同请求丢弃包数"},
    {'name_en': "udp_filter", 'name_cn': "过滤不发往后端端口的包数"},
    {'name_en': "fattack", 'name_cn': "泛域名攻击"},
]

#prefetch
PREFETCH_EN_CH_MAP = [
    {'name_en': "rcv_impact", 'name_cn': "DNS响应成功包效果数"},
    {'name_en': "rcv_pkt", 'name_cn': "DNS响应成功包数"},
    {'name_en': "snd_fail", 'name_cn': "超时重试数"},
    {'name_en': "snd_node", 'name_cn': "待刷新的节点数"},
    {'name_en': "snd_pkt", 'name_cn': "发送ttl刷新包数"},
    {'name_en': "ttl_expire", 'name_cn': "ttl超时包数"},
]

#view
VIEW_EN_CH_MAP = [
    {'name_en': "time", 'name_cn': "采集时间"},
    {'name_en': "in_req", 'name_cn': "总请求数"},
    {'name_en': "top_in_req", 'name_cn': "请求中热点域名数"},
    {'name_en': "top_hit_req", 'name_cn': "热点域名命中数"},
    {'name_en': "backup_in_req", 'name_cn': "作为备份接收请求数"},
    {'name_en': "backup_out_req", 'name_cn': "向备份发送请求数"},
    {'name_en': "hit_req", 'name_cn': "命中请求数"},
    {'name_en': "fwd_req", 'name_cn': "原生请求转发数"},
    {'name_en': "fwd_timeout", 'name_cn': "原生请求超时数"},
]

#qps
QPS_EN_CH_MAP = [
    {'name_en': "SUM", 'name_cn': "总请求个数"},
    {'name_en': "IN_A", 'name_cn': "A记录请求个数"},
    {'name_en': "IN_AAAA", 'name_cn': "AAAA记录请求个数"},
    {'name_en': "OTHER", 'name_cn': "其他请求个数"},
]

#域名topn移动平均线
TOPN_MA_EN_CH_MAP = [
    {'name_en': "Count", 'name_cn': "Count"},
    {'name_en': "MA", 'name_cn': "MA移动平均值"},
]