#coding=utf-8
__author__ = 'weiguo.cwg'


import logging
from django.db import models

log = logging.getLogger(__name__)


class PdnsClientIP(models.Model):
    id = models.BigIntegerField(max_length=20)
    gmt_create = models.DateTimeField(auto_now_add=True)
    client_ip = models.BigIntegerField(max_length=20)
    client_real_ip = models.BigIntegerField(max_length=20)

    class Meta:
        db_table = u'pdns_client_ip'


#TODO 表结构需要重新设计，否则每新增一个机房，表结构也得跟着变动 add by weiguo.cwg
class PdnsTotalQuery(models.Model):
    id = models.BigIntegerField(max_length=20)
    gmt_create = models.DateTimeField(auto_now_add=True)
    cm9 = models.BigIntegerField(max_length=20)
    cm10 = models.BigIntegerField(max_length=20)
    st3 = models.BigIntegerField(max_length=20)

    class Meta:
        db_table = u'pdns_total_query'


class PdnsQueryType(models.Model):
    id = models.BigIntegerField(max_length=20)
    gmt_create = models.DateTimeField(auto_now_add=True)
    q_type = models.CharField(max_length=20)
    q_count = models.BigIntegerField(max_length=20)

    class Meta:
        db_table = u'pdns_query_type'


class PdnsQueryLen(models.Model):
    id = models.BigIntegerField(max_length=20)
    gmt_create = models.DateTimeField(auto_now_add=True)
    q_len = models.IntegerField(max_length=8)
    q_count = models.BigIntegerField(max_length=20)

    class Meta:
        db_table = u'pdns_query_len'


class PdnsQueryLabel(models.Model):
    id = models.BigIntegerField(max_length=20)
    gmt_create = models.DateTimeField(auto_now_add=True)
    q_label = models.IntegerField(max_length=8)
    q_count = models.BigIntegerField(max_length=20)

    class Meta:
        db_table = u'pdns_query_label'