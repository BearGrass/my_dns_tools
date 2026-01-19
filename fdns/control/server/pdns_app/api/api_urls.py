#coding=utf-8

from django.conf.urls import *

from api_views import *

urlpatterns = patterns('',
    url(r'rr/delete_record/$|rr/delete_record$|rr/delRr$|rr/delRr/$', delete_record),
    url(r'app_user/add_app_user$', add_app_user),
    url(r'app_user/delete_app_user$', delete_app_user),
)
