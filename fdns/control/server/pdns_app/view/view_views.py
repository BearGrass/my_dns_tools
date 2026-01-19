#coding=utf-8
import logging
import traceback
import json

from django.contrib.auth.decorators import permission_required
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import render_to_response

from view_manager import ViewManager
from pdns import utils, constants

log = logging.getLogger(__name__)

def view_menu_tree(request):
    '''
    左侧导航栏的view树信息
    '''
    # 万网版本
    children = [
        {'id': 'view-list', 'text': 'view组管理', 'leaf': True},
    ]
    tree = {'id': '0', 'children': children}
    return HttpResponse(json.dumps(tree))

def view_page(request):
    args = {}
    args["BASE_PAGE_SIZE"] = constants.BASE_PAGE_SIZE
    return render_to_response("view/view_manage.html", args)

def view_list(request):
    try:
        view_name = request.GET.get("view_name", "")
        page = request.GET.get("page", 1)
        limit = request.GET.get("limit", constants.BASE_PAGE_SIZE)
        view_list, pager = ViewManager.view_list(view_name, page, limit)
        return HttpResponse(json.dumps({"result": view_list, "total": pager.count},default=utils.default_json_hanlder))
    except Exception, e:
        print traceback.format_exc()
        log.error(traceback.format_exc())
        return HttpResponse(json.dumps({"result": "error"}))


@login_required
def view_name_list(request):
    """
    获得所有Line的名字列表
    """
    view_list = ViewManager.get_view_dict_list_by_cluster_id()
    view_detail_list = []
    for view in view_list:
        if view.get("name") == 'default':
            view_detail_list.append({"name": 'DEFAULT'})
        else:
            view_detail_list.append({"name": view.get("name")})
    json_result = json.dumps({'result': view_detail_list})
    return HttpResponse(json_result)

@login_required
@permission_required("pdns.update", raise_exception=True)
def add_view(request):
    try:
        view_info = json.loads(request.POST.get("view_info", "{}"))
        ViewManager.add_view(view_info)
        return HttpResponse(json.dumps({"result": "success"}))
    except Exception, e:
        log.error(traceback.format_exc())
        return HttpResponse(json.dumps({"result": "error"}))

@login_required
@permission_required("pdns.update", raise_exception=True)
def delete_view(request):
    try:
        view_info = json.loads(request.POST.get("view_info", "{}"))
        ViewManager.delete_view(view_info)
        return HttpResponse(json.dumps({"result": "success"}))
    except Exception, e:
        log.error(traceback.format_exc())
        return HttpResponse(json.dumps({"result": "error"}))

@login_required
@permission_required("pdns.update", raise_exception=True)
def update_view(request):
    try:
        view_info = json.loads(request.POST.get("view_info", "{}"))
        ViewManager.update_view(view_info)
        return HttpResponse(json.dumps({"result": "success"}))
    except Exception, e:
        log.error(traceback.format_exc())
        return HttpResponse(json.dumps({"result": "error"}))

def get_view(reqeust):
    try:
        id = reqeust.POST.get("id")
        view_dict = ViewManager.get_view_info(id)
        if view_dict:
            return HttpResponse(json.dumps({"result": view_dict},default=utils.default_json_hanlder))
        else:
            raise HttpResponse(json.dumps({"result": "error", "message": "server not exits"}))
    except Exception, e:
        return HttpResponse(json.dumps(e.args[0]))