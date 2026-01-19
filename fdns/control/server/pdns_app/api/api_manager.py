# coding=utf-8

import logging
import warnings
import MySQLdb
import time

warnings.filterwarnings("ignore", category=MySQLdb.Warning)

log = logging.getLogger(__name__)

from pdns import utils, error_code
from pdns_app.user.user_model import BucAuthUser

class APP_Manager(object):
    @staticmethod
    def add_app_user(app):
        if app.is_superuser():
            if not app.is_appid_exist():
                # 向auth_user表中加入用户
                app_object = app.add_app_object()
                app_object.password = utils.md5_encode("%s%s" % (app_object.username, time.time()))
                app_object.save()

                return {
                    "appId": app_object.username,
                    "appKey": app_object.password,
                    "is_superuser": bool(app_object.is_superuser),
                }
            else:
                raise Exception(error_code.APP_USER_EXIST)
        else:
            raise Exception(error_code.SUPERUSER_ONLY)


    @staticmethod
    def delete_app_user(app):
        if app.is_superuser():
            if app.is_appid_exist():
                # 删除auth_user表里的人
                app_object = app.app_object
                app_object_id = app_object.id
                app_object.delete()
                # 删除buc_auth_user表里的数据
                BucAuthUser.objects.filter(user_id=app_object_id).delete()
            else:
                raise Exception(error_code.APP_USER_NOT_EXIST)
        else:
            raise Exception(error_code.SUPERUSER_ONLY)