# -*- coding: utf-8 -*-
import urllib

import simplejson
import function
from django.shortcuts import render_to_response
from django.http import HttpResponseRedirect
from django.http import HttpResponse
from django.template import RequestContext
from django.utils.simplejson import dumps
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login as auth_login

from settings import ALI_SSO_SERVER, GIT_REF, GIT_SHA1, TITLE_INFO_BAR


@login_required
def index(request):
    args = RequestContext(request)
    username = request.user.username
    args['username'] = username
    args['ADMS_version'] = GIT_REF + '（'+ GIT_SHA1 +'）'
    args['title_info_bar'] = TITLE_INFO_BAR
    return render_to_response('index.html', args)


@login_required
def welcome(request):
    args = RequestContext(request)
    return render_to_response('welcome.html', args)


def login(request):
    sso_token = request.GET.get('SSO_TOKEN')
    result = get_login_info_from_sso(sso_token)
    result_content = simplejson.loads(result.get('content'))
    username = result_content.get('emailPrefix')
    first_name = result_content.get('firstName')
    last_name = result_content.get('lastName')
    email = result_content.get('emailAddr')
    buc_sso_id = result_content.get('id')
    user = authenticate(username=username, first_name=first_name,last_name=last_name,email=email, buc_sso_id=buc_sso_id)
    auth_login(request, user)
    return HttpResponseRedirect('/')


# noinspection PyBroadException
def logout(request):
    response = HttpResponseRedirect('/')
    try:
        response.delete_cookie('SSO_TOKEN')
        response.delete_cookie('USER_COOKIE')
        response.delete_cookie('LAST_HEART_BEAT_TIME')
        return response
    except Exception:
        return response


def get_login_info_from_sso(sso_token):
    sso_server = ALI_SSO_SERVER
    param_dict = {}
    param_dict['SSO_TOKEN'] = sso_token
    param_dict['RETURN_USER'] = 'true'
    params = urllib.urlencode(param_dict)
    server_redirect_url = "https://%s/rpc/sso/communicate.json" % (sso_server)
    f = urllib.urlopen(server_redirect_url, params)
    result = f.read()
    return simplejson.loads(result)


def get_current_user(request):
    username = request.user.username
    change = request.user.has_perm('sites.change_site')
    json = dumps({'username':username,'topo_edit':change})
    return HttpResponse(json)


def status_check(request):
    return HttpResponse(200)