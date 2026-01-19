#coding=utf-8

import logging

from view_models import View
from pdns import utils
from pdns import error_code
from pdns_app.server.server_model import PdnsServer

log = logging.getLogger(__name__)

class ViewManager(object):
    @staticmethod
    def get_view_dict_list():
        """
        得到所有view的列表
        """
        return View.objects.all().values(*View.default_selct_colums())


    @staticmethod
    def view_list(view_name, page, limit):
        """
        获取server(forwarder/cdn)列表
        """
        params = {}
        params["name__icontains"] = view_name
        views, pager = utils.page_utils(
            View.objects.select_related().filter(**params), page, page_size=limit, RETURN_DICT=False
        )
        views_dict = [view.to_json() for view in views]
        return views_dict, pager

    @staticmethod
    def add_view(view_info):
        """
        添加view
        """
        if view_info.get("fallback_name") not in (None, ''):
            fallback_view = ViewManager.get_view_by_name(view_info.get("fallback_name"))
            fallback_id = fallback_view.id
        else:
            fallback_id = None
        view = View(**{"name": view_info.get("name"), "cn_name": view_info.get("name"), "fallback_id": fallback_id})
        view.save()

    @staticmethod
    def delete_view(view_info):
        """
        删除view
        """
        view_id = view_info.get("id")
        view_obj = View.objects.get(id=int(view_id))

        #将二级cdn结点的view_id置成None
        cdn_ids = view_obj.cdn_ids
        if cdn_ids:
            cdn_id_list = cdn_ids.split()
            for cdn_id in cdn_id_list:
                cdn_objs = PdnsServer.objects.filter(id=int(cdn_id))
                for cdn_obj in cdn_objs:
                    cdn_obj.view_id = None
                    cdn_obj.save()

        #将fallback到该view的view的fallback置成None
        views_fallback = View.objects.filter(fallback_id = int(view_id))
        for view_fallback in views_fallback:
            view_fallback.fallback_id = None
            view_fallback.save()

        #删除该view
        view_obj.delete()


    @staticmethod
    def get_view_info(id):
        """
        获取view
        """
        view_obj = View.objects.get(id=id)
        view_dict = view_obj.to_json()
        fallback_id = view_dict.get("fallback_id")
        fallback_views = View.objects.filter(id=fallback_id)
        if len(fallback_views) > 0:
            view_dict["fallback_name"] = fallback_views[0].name
        else:
            view_dict["fallback_name"] = ''
        return view_dict

    @staticmethod
    def update_view(view_info):
        """
        更新view
        """
        view_id = view_info.get("id")
        view_obj = View.objects.get(id=view_id)
        if view_info.get("fallback_name") in (None, ''):
            view_obj.fallback_id = None
        else:
            if view_obj.name == view_info.get("fallback_name"):
                raise Exception("update view and fallback view is same")
            fallback_view = ViewManager.get_view_by_name(view_info.get("fallback_name"))
            view_obj.fallback_id = fallback_view.id
        view_obj.name = view_info.get("name")
        view_obj.cn_name = view_info.get("name")
        view_obj.save()

    @staticmethod
    def get_view_id_by_name(view_name):
        view_objs = View.objects.filter(name=view_name)
        if len(view_objs) <= 0:
            raise Exception(error_code.VIEW_NOT_EXIST)
        else:
            return view_objs[0].id

    @staticmethod
    def get_view_name_by_id(view_id):
        view_objs = View.objects.filter(id=int(view_id))
        if len(view_objs) <= 0:
            raise Exception(error_code.VIEW_NOT_EXIST)
        else:
            return view_objs[0].name

    @staticmethod
    def get_view_by_id(view_id):
        view_objs = View.objects.filter(id=int(view_id))
        if len(view_objs) <= 0:
            raise Exception(error_code.VIEW_NOT_EXIST)
        else:
            return view_objs[0]

    @staticmethod
    def get_view_by_name(view_name):
        view_objs = View.objects.filter(name=view_name)
        if len(view_objs) <= 0:
            raise Exception(error_code.VIEW_NOT_EXIST)
        else:
            return view_objs[0]

