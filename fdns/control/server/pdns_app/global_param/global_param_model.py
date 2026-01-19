#coding=utf-8
import logging
from django.db import models

log = logging.getLogger(__name__)

class GlobalParam(models.Model):
    id = models.IntegerField()
    name = models.CharField(max_length=128)
    value = models.CharField(max_length=128)
    ttl = models.IntegerField(default=0)
    comment = models.CharField(max_length=128)
    gmt_created = models.DateTimeField(editable=False, auto_now_add=True)
    gmt_modified = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = u'global_param'