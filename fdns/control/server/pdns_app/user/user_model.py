#coding=utf-8
__author__ = 'pinghua.wph'

from django.db import models

class BucAuthUser(models.Model):
    user_id = models.IntegerField()
    buc_sso_id = models.CharField(max_length=255)

    class Meta:
        db_table = u'buc_auth_user'
