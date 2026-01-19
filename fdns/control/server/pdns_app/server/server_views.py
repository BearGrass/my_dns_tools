#coding=utf-8
from django.contrib.auth.decorators import permission_required
from django.contrib.auth.decorators import login_required
from django.template import RequestContext
from django.shortcuts import render_to_response
from django.http import HttpResponse

import json
import traceback
import logging

from pdns_app.server.server_manager import PdnsServerManager
from pdns import utils, constants

log = logging.getLogger(__name__)


@login_required
def server_menu_tree(request):
    """
    返回服务器管理分栏下面有的菜单类目
    """
    children = [
        {'id': 'pdns-server-list', 'text': '服务器管理', 'leaf': True},
    ]
    tree = {'id': '0', 'children': children}
    return HttpResponse(json.dumps(tree))

def pdns_server_manage(request):
    '''
    服务器界面
    '''
    args = RequestContext(request)
    return render_to_response("server/pdns_server_manager.html", args)

@login_required
@permission_required("pdns.update",raise_exception=True)
def add_pdns_server(request):
    try:
        pdns_server = json.loads(request.POST.get("pdns_server", "{}"))
        PdnsServerManager.add_pdns_server(pdns_server)
        return HttpResponse(json.dumps({"result": "success"}))
    except Exception, e:
        log.error(traceback.format_exc())
        return HttpResponse(json.dumps({"result": "error", "message": "添加pdns server异常"}))

@login_required
@permission_required("pdns.update", raise_exception=True)
def delete_pdns_server(request):
    try:
        pdns_server = json.loads(request.POST.get("pdns_server", "{}"))
        PdnsServerManager.delete_pdns_server(pdns_server)
        return HttpResponse(json.dumps({"result": "success"}))
    except Exception, e:
        log.error(traceback.format_exc())
        return HttpResponse(json.dumps({"result": "error", "message": "删除pdns server异常"}))

def pdns_server_list(request):
    try:
        pdns_server_name = request.GET.get("server_name", "")
        page = request.GET.get("page", 1)
        limit = request.GET.get("limit", constants.BASE_PAGE_SIZE)
        server_list_info = PdnsServerManager.pdns_server_list(pdns_server_name)
        server_list, pager = utils.page_utils(server_list_info, page, page_size=limit, RETURN_DICT=False)
        return HttpResponse(json.dumps({"result": server_list.object_list, "total": pager.count}, default=utils.default_json_hanlder))
    except Exception, e:
        print traceback.format_exc()
        log.error(traceback.format_exc())
        return HttpResponse(json.dumps({"result": "error"}))

@login_required
@permission_required("pdns.update", raise_exception=True)
def update_pdns_server(request):
    try:
        pdns_server = json.loads(request.POST.get("pdns_server", "{}"))
        PdnsServerManager.update_pdns_server(pdns_server)
        return HttpResponse(json.dumps({"result": "success"}))
    except Exception, e:
        log.error(traceback.format_exc())
        return HttpResponse(json.dumps({"result": "error", "message": "更新pdns server异常"}))

def pdns_server_info(request):
    try:
        id = request.POST.get("id")
        pdns_server_dict = PdnsServerManager.get_server_info(id)
        if pdns_server_dict:
            return HttpResponse(json.dumps({"result": pdns_server_dict},default=utils.default_json_hanlder))
        else:
            raise HttpResponse(json.dumps({"result": "error", "message": "server not exits"}))
    except Exception, e:
        return HttpResponse(json.dumps(e.args[0]))

def report_server_status(request):
    try:
        param = json.loads(request.POST.get("param"))
        if param in (None, ""):
            return HttpResponse(json.dumps({"msg": "param error", "status": -1}))

        res = PdnsServerManager.report_server_status(param)
        return HttpResponse(json.dumps({"status": res["status"], "msg": res["msg"]}))

    except:
        log.error("report_server_status, error:" % traceback.format_exc())
        return HttpResponse(json.dumps({"msg": "unknow error", "status": -1}))

