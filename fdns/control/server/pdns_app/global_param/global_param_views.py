#coding=utf-8
from django.contrib.auth.decorators import permission_required
from django.contrib.auth.decorators import login_required
from django.utils.simplejson import dumps
from django.template import RequestContext
from django.shortcuts import render_to_response
from django.http import HttpResponse

import json
import traceback
import logging

from pdns_app.global_param.global_param_manager import GlobalParamManager
from pdns.constants import BASE_PAGE_SIZE
from pdns import utils

log = logging.getLogger(__name__)

@login_required
def global_param_menu_tree(request):
    """
    返回全局参数管理分栏下面有的菜单类目
    """
    children = [{'id': 'api-global-param', 'text': '全局控制', 'leaf': True},
                ]
    tree = {'id': '0', 'children': children}
    json = dumps(tree)
    return HttpResponse(json)

@login_required
def global_param(request):
    '''
    全局参数增删改查界面
    '''
    args = RequestContext(request)
    args["BASE_PAGE_SIZE"] = BASE_PAGE_SIZE
    return render_to_response("global_param/global_param.html", args)

def global_param_list(request):
    try:
        global_param_name = request.GET.get("global_param_name", "")
        page = request.GET.get("page", 1)
        limit = request.GET.get("limit", BASE_PAGE_SIZE)
        global_param_info, pager = GlobalParamManager.get_global_param_info(global_param_name, page, page_size=limit)
        return HttpResponse(json.dumps({"result": global_param_info, "total": pager.count},default=utils.default_json_hanlder))
    except Exception, e:
        log.error(traceback.format_exc())
        return HttpResponse(json.dumps({"result": "error"}))

@login_required
@permission_required("pdns.update", raise_exception=True)
def delete_global_param(request):
    try:
        global_param = json.loads(request.POST.get("global_param", "{}"))
        GlobalParamManager.delete_global_param(global_param)
        return HttpResponse(json.dumps({"result": "success"}))
    except:
        log.error(traceback.format_exc())
        return HttpResponse(json.dumps({"result": "error"}))

@login_required
@permission_required("pdns.update", raise_exception=True)
def update_global_param(request):
    try:
        global_param = json.loads(request.POST.get("global_param", "{}"))
        GlobalParamManager.update_global_param(global_param)
        return HttpResponse(json.dumps({"result": "success"}))
    except:
        log.error(traceback.format_exc())
        return HttpResponse(json.dumps({"result": "error"}))


@login_required
@permission_required("pdns.update", raise_exception=True)
def add_global_param(request):
    try:
        global_param = json.loads(request.POST.get("global_param", "{}"))
        GlobalParamManager.add_global_param(global_param)
        return HttpResponse(json.dumps({"result": "success"}))
    except:
        log.error(traceback.format_exc())
        return HttpResponse(json.dumps({"result": "error"}))

