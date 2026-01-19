#coding=utf-8
import logging
import time
import traceback

from pdns import utils, error_code, constants
from pdns_app.global_param.global_param_model import GlobalParam

log = logging.getLogger(__name__)

class GlobalParamManager(object):
    @staticmethod
    def add_global_param(global_param):
        """
        添加全局控制参数
        """
        record = GlobalParam(**{"name": global_param.get("name"),
                                "value": global_param.get("value"),
                                "ttl": global_param.get("ttl"),
                                "comment": global_param.get("comment"),
                            })
        record.save()

    @staticmethod
    def update_global_param(global_param):
        """
        更新全局控制参数
        """
        global_param_id = global_param.get("id")
        global_param_db = GlobalParam.objects.get(id=global_param_id)
        global_param_db.name = global_param.get("name")
        global_param_db.value = global_param.get("value")
        global_param_db.ttl = global_param.get("ttl")
        global_param_db.comment = global_param.get("comment")
        global_param_db.gmt_modified = time.time()
        global_param_db.save()

    @staticmethod
    def delete_global_param(global_param):
        """
        删除全局控制参数
        """
        global_param_id = global_param.get("id")
        GlobalParam.objects.filter(id=global_param_id).delete()

    @staticmethod
    def get_global_param_info(name, page, page_size=constants.BASE_PAGE_SIZE):
        """
        获取全局控制参数
        """
        try:
            if name == '':
                object_list = GlobalParam.objects.all()
            else:
                object_list = GlobalParam.objects.filter(name__contains=name)
            global_param_info, pager = utils.page_utils(object_list, page, page_size=page_size)
            return global_param_info, pager
        except:
            log.error(traceback.format_exc())
            return None, None