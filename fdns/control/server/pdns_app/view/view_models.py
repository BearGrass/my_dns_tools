#coding=utf-8
import logging
from django.db import models

log = logging.getLogger(__name__)

class View(models.Model):
    """
    线路
    """
    id = models.IntegerField(primary_key=True)
    name = models.CharField(max_length=765)
    cn_name = models.CharField(max_length=765, blank=True)
    desc = models.TextField(null=True, blank=True, db_column="descr")
    isp_simulate_ip = models.CharField(null=True,max_length=765)
    fallback_id = models.IntegerField(null=True, blank=True)#默认都fallback到default view
    cdn_ids = models.TextField(null=True, blank=True)

    class Meta:
        db_table = u'view'

    @staticmethod
    def default_selct_colums():
        return ['id', 'name', 'cn_name', 'desc', 'isp_simulate_ip', 'fallback_id', 'cdn_ids']

    def set_data(self, param_dict):
        for key in param_dict:
            self.__dict__[key] = param_dict.get(key)

    def to_json(self):
        return dict(
            id=self.id,
            name=self.name,
            cn_name=self.cn_name,
            desc=self.desc,
            isp_simulate_ip=self.isp_simulate_ip,
            fallback_id=self.fallback_id,
            cdn_ids=self.cdn_ids
        )


