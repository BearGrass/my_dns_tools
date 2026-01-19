#coding=utf-8
import logging
import httplib
import traceback
import json
import time
from django.db import transaction

from pdns import utils, error_code, constants
from pdns_app.server.server_model import PdnsServer, TmpServerStatus
from pdns_app.view.view_manager import ViewManager

log = logging.getLogger(__name__)

class PdnsServerManager(object):
    @staticmethod
    def add_pdns_server(pdns_server):
        """
        添加pdns server（forwarder/cdn)
        """
        if pdns_server.get("type") == constants.SERVER_TYPE_FWD:
            server = PdnsServer(**{"ip": pdns_server.get("ip"), "host": pdns_server.get("host"),"type": pdns_server.get("type")})
            server.save()
        if pdns_server.get("type") == constants.SERVER_TYPE_CDN:
            view = ViewManager.get_view_by_name(pdns_server.get("view_name"))
            #加入pdns_server表中
            server = PdnsServer(**{"ip": pdns_server.get("ip"), "host": pdns_server.get("host"),"type": pdns_server.get("type"), "view_id": view.id})
            server.save()
            #将pdns server.id加入view.cdn_ids中
            cdn_id_list = view.cdn_ids
            if cdn_id_list in (None, ''):
                cdn_id_list = str(server.id)
            else:
                cdn_id_list = cdn_id_list + ' ' + str(server.id)
            view.cdn_ids = cdn_id_list
            view.save()

    @staticmethod
    def delete_pdns_server(pdns_server):
        """
        删除pdns server（forwarder/cdn)
        """
        server_id = pdns_server.get("id")
        pdns_servers = PdnsServer.objects.filter(id=server_id)
        if len(pdns_servers) < 0:
            raise Exception(error_code.PDNS_SERVER_NOT_EXIST)
        pdns_server = pdns_servers[0]
        if constants.SERVER_TYPE_CDN == pdns_server.type:
            #将cdn.id中view.cdn_ids中删除
            if pdns_server.view_id:
                view = ViewManager.get_view_by_id(pdns_server.view_id)
                str_cdn_ids = view.cdn_ids
                if str_cdn_ids not in (None, ''):
                    cdn_ids_list = str_cdn_ids.split()
                    if str(pdns_server.id) in cdn_ids_list:
                        cdn_ids_list.remove(str(pdns_server.id))
                        str_cdn_ids = ' '.join(cdn_ids_list)
                    view.cdn_ids = str_cdn_ids
                    view.save()
        pdns_server.delete()

    @staticmethod
    def pdns_server_list(pdns_server_name):
        """
        获取pdns server(forwarder/cdn)列表
        """
        params = {}
        params["host__icontains"] = pdns_server_name
        pdns_servers=PdnsServer.objects.filter(**params)
        pdns_servers_dict = []
        for pdns_server in pdns_servers:
            pdns_server_dict = pdns_server.to_json()
            if pdns_server.type == constants.SERVER_TYPE_FWD:
                view_name = ""
            else:
                if pdns_server.view_id:
                    view_name = ViewManager.get_view_name_by_id(pdns_server.view_id)
                else:
                    view_name = ""
            pdns_server_dict["view_name"] = view_name
            pdns_servers_dict.append(pdns_server_dict)
        return pdns_servers_dict

    @staticmethod
    def update_pdns_server(pdns_server):
        """
        更新pdns server（forwarder/cdn),不可以更改pdns server的类型
        forwarder可以更改的内容：ip, host
        cdn可以更改的内容：ip, host, view_name
        """
        pdns_server_db = PdnsServer.objects.get(id=pdns_server.get("id"))
        pdns_server_db.ip = pdns_server.get("ip")
        pdns_server_db.host = pdns_server.get("host")
        if pdns_server_db.type == constants.SERVER_TYPE_CDN:
            new_view = ViewManager.get_view_by_name(pdns_server.get("view_name"))
            if pdns_server_db.view_id != new_view.id:
                #将server id在之前的view中删除
                if pdns_server_db.view_id:
                    old_view = ViewManager.get_view_by_id(int(pdns_server_db.view_id))
                    if old_view.cdn_ids not in (None, ''):
                        str_cdn_ids = old_view.cdn_ids
                        cdn_ids_list = str_cdn_ids.split()
                        if str(pdns_server_db.id) in cdn_ids_list:
                            cdn_ids_list.remove(str(pdns_server_db.id))
                        str_cdn_ids = ' '.join(cdn_ids_list)
                        old_view.cdn_ids = str_cdn_ids
                        old_view.save()
                #将server id加入到新的view中
                cdn_id_list = new_view.cdn_ids
                if cdn_id_list in (None, ''):
                    cdn_id_list = str(pdns_server_db.id)
                else:
                    cdn_id_list = cdn_id_list + ' ' + str(pdns_server_db.id)
                new_view.cdn_ids = cdn_id_list
                new_view.save()
                #保存pdns server中的view id
                pdns_server_db.view_id = new_view.id
        pdns_server_db.save()

    @staticmethod
    def get_server_info(id):
        """
        获取pdns server（forwarder/cdn)
        """
        pdns_server=PdnsServer.objects.get(id=int(id))
        pdns_server_dict = pdns_server.to_json()
        if pdns_server.view_id in (None, ""):
            view_name = ""
        else:
            view_name = ViewManager.get_view_name_by_id(pdns_server.view_id)
        pdns_server_dict["view_name"] = view_name
        return pdns_server_dict

    @staticmethod
    def get_server_with_ip(ip):
        """
        获取pdns server（forwarder/cdn)
        """
        try:
            pdns_server=PdnsServer.objects.get(ip=ip)
            pdns_server_dict = pdns_server.to_json()
            if pdns_server.view_id in (None, ""):
                view_name = ""
            else:
                view_name = ViewManager.get_view_name_by_id(pdns_server.view_id)
            pdns_server_dict["view_name"] = view_name
            return pdns_server_dict
        except:
            log.error("get_server_with_ip, error:" % traceback.format_exc())
            return None

    @staticmethod
    def report_server_status(param):
        try:
            pdns_server_dict = PdnsServerManager.get_server_with_ip(param["ip"])
            if None == pdns_server_dict:
                return {"status":-1,"msg": "unknow server"}

            t_status = TmpServerStatus(host_id=pdns_server_dict["id"], ip=pdns_server_dict["ip"],\
                                       status=json.dumps(param["status"]), host_id=pdns_server_dict["id"])
            t_status.save()
            return {"status":0,"msg": "ok"}

        except:
            log.error("get_server_with_ip, error:" % traceback.format_exc())
            return {"status":-1,"msg": "unknow error"}
