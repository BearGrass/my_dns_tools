#coding=utf-8
__author__ = 'weiguo.cwg'


pdns_servers_add = [
    #格式，"type(必填,cdn/forwarder),ip(必填),host(选填),port(选填，9999)",
    "cdn,111.13.56.95,111.13.56.95,9999",
    "cdn,111.13.56.96",
    "forwarder,10.165.87.99,forwarder01.pdns.st,9999"
]


pdns_servers_del = [
    #格式，"type(必填,cdn/forwarder),ip(必填)",
    "cdn,111.13.56.95",
    "forwarder,10.165.87.99"
]
