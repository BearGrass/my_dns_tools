#coding=utf-8
__author__ = 'zhaolin.huang'
from django.conf.urls import *

from user_views import *
from pdns_app.api.api_views import delete_app_user

urlpatterns = patterns('',
    url(r'^user_info/$', get_users_info),
    url(r'^get_single_user_info/$', get_single_user_info),
    url(r'^delete_user/$', delete_app_user),#删除auth_user和buc_auth_user中的数据
    url(r'^update_user_password/$', update_user_password),

)