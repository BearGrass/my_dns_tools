#coding=utf-8
import logging
from pdns_app.user.user_model import BucAuthUser
from django.contrib.auth.models import User
from pdns import utils, constants

log = logging.getLogger(__name__)

class UserManager(object):
    @staticmethod
    def buc_get_or_creat(username=None,first_name=None,last_name=None,email=None,buc_sso_id=None):
        user, created = User.objects.get_or_create(username=username,first_name=first_name,last_name=last_name,email=email)
        if created:
            #save_buc_info
            created = UserManager.save_buc_info(user,buc_sso_id=buc_sso_id)
        return user, created

    @staticmethod
    def save_buc_info(user, buc_sso_id=None):
        try:
            buc_user_obj = BucAuthUser.objects.get(user_id=user.id)
            if buc_user_obj.buc_sso_id != buc_sso_id:
                # 更新buc_sso_id
                buc_user_obj.buc_sso_id = buc_sso_id
                buc_user_obj.save()
        except:
            # 数据库中可能没有该记录，或者存在多条该记录
            buc_user_objs = BucAuthUser.objects.filter(user_id=user.id)
            if len(buc_user_objs) != 0:
                buc_user_objs.delete()
            buc_user_obj = BucAuthUser(user_id=user.id, buc_sso_id=buc_sso_id)
            buc_user_obj.save()
        return True

    @staticmethod
    def get_user_info(**para):
        user_dict_list = utils.get_dict_result(User, *(), **para)
        return user_dict_list

    @staticmethod
    def get_user(**para):
        user = utils.get_model_nullable(User, **para)
        return user

    @staticmethod
    def authorize_superuser(user_id):
        user = User.objects.get(id=user_id)
        user.is_superuser = True
        user.save()

    @staticmethod
    def add_user(**para):
        user = User(**para)
        user.save()
        return user