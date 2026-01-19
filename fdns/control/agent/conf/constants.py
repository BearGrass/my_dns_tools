#coding=utf-8
__author__ = 'weiguo.cwg'

SERVER_TYPE_FWD = "forwarder"
SERVER_TYPE_REDIS = "redis"
SERVER_TYPE_CDN = "cdn"

A = 1
NS = 2
CNAME = 5
SOA = 6
PTR = 12
MX = 15
TXT = 16
AAAA = 28
SRV = 33


_by_text = {
    'A' : A,
    'NS' : NS,
    'CNAME' : CNAME,
    'SOA' : SOA,
    'PTR' : PTR,
    'MX' : MX,
    'TXT' : TXT,
    'AAAA' : AAAA,
    'SRV' : SRV
    }