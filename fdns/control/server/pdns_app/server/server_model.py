#coding=utf-8
import logging
from django.db import models

from pdns import constants

log = logging.getLogger(__name__)

class PdnsServer(models.Model):
    id = models.IntegerField()
    ip = models.CharField(max_length=255)
    host = models.CharField(max_length=255, null=True)
    port = models.IntegerField(default=constants.AGENT_PORT)
    type = models.CharField(max_length=64)
    status = models.CharField(max_length=64, default='offline')
    gmt_created = models.DateTimeField(auto_now_add=True)
    gmt_modified = models.DateTimeField()
    first_error_time = models.DateTimeField(null=True, blank=True)
    pdns_version = models.CharField(max_length=128, null=True)
    agent_version = models.CharField(max_length=128, null=True)
    agent_status = models.CharField(max_length=32, default='offline')
    view_id = models.IntegerField(null=True, blank=True)

    class Meta:
        db_table = u'pdns_server'

    def to_json(self):
        return dict(
            id=self.id,
            ip=self.ip,
            host=self.host,
            port=self.port,
            type=self.type,
            status=self.status,
            pdns_version=self.pdns_version,
            agent_version=self.agent_version,
            agent_status=self.agent_status,
            view_id = self.view_id
        )


class TmpServerStatus(models.Model):
    id = models.IntegerField()
    host_id = models.IntegerField()
    ip = models.CharField(max_length=32)
    gmt_created = models.DateTimeField(auto_now_add=True)
    gmt_modified = models.DateTimeField()
    status = models.TextField()

    class Meta:
        db_table = u'tmp_server_status'

    def to_json(self):
        return dict(
            id=self.id,
            ip=self.ip,
            host_id=self.host_id,
            status=self.status,
            gmt_created = self.gmt_created,
            gmt_modified = self.gmt_modified
        )