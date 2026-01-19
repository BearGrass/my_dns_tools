#coding=utf-8

import json
import traceback
import logging
import time

from django.contrib.auth.decorators import permission_required, user_passes_test, login_required
from django.views.decorators.csrf import csrf_exempt
from django.template import RequestContext
from django.shortcuts import render_to_response
from django.http import HttpResponse
from pdns import utils, constants
from user_manager import UserManager
from rest_framework.parsers import JSONParser

log = logging.getLogger(__name__)

@login_required
@csrf_exempt
def get_users_info(request):
    try:
        get_user_info = UserManager.get_user_info()
        return HttpResponse(json.dumps(get_user_info, default=utils.default_json_hanlder))
    except Exception, e:
        log.error(traceback.format_exc())
        return HttpResponse(json.dumps(e.args[0]))


@login_required
@csrf_exempt
def get_single_user_info(request):
    """
    :param request:
    :return:
    """
    try:
        if request.method == "POST":
            request_info = JSONParser().parse(request)
            username = request_info.get('username')
            user = UserManager.get_user(**{"username": username})
            user_info = utils.model_to_dict(user)
            return HttpResponse(json.dumps(user_info, default=utils.default_json_hanlder))
    except Exception, e:
        log.error(traceback.format_exc())
        return HttpResponse(json.dumps(e.args[0]))

@login_required
def update_user_password(request):
    try:
        if request.method == "POST":
            request_info = JSONParser().parse(request)
            username = request_info.get('config_app_id')
            password = utils.md5_encode("%s%s" % (username, time.time()))
            user = UserManager.get_user(**{"username": username})
            user.password = password
            user.save()
            return HttpResponse(json.dumps({"result": "SUCCESS", "passwd": password}))
    except Exception, e:
        log.error(traceback.format_exc())
        return HttpResponse(json.dumps(e.args[0]))
