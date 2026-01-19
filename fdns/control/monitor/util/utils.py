#coding=utf-8
__author__ = 'weiguo.cwg'


def format_domain_name(zone, rr):
    """
    如果不是全域名，则改成全域名
    """
    if str(rr).endswith("."):
        if str(rr).endswith(zone):
            return rr
        else:
            raise Exception("error rr:%s, zone:%s" % (rr, zone))
    else:
        if rr:
            return "%s.%s" % (rr, zone)
        else:
            return zone
