# -*- coding: utf-8 -*-
from django.conf.urls.defaults import *
from django.contrib.auth.views import login, logout

from server import server_urls
from user import user_urls
from global_param import global_param_urls
from view import view_urls
from api import api_urls
from data_display import data_urls
from app_views import status_check

urlpatterns = patterns('pdns_app.app_views',
                       url(r'^$', 'index', name='index'),
                       url(r'^welcome/', 'welcome', name='welcome'),
                       url(r'^login/$', login,
                           kwargs=dict(template_name='login.html'),
                           name='login'),
                       url(r'^logout/$', logout, kwargs=dict(next_page='/'),
                           name='logout'),
                       url(r'^server/', include(server_urls)),
                       url(r'^global_param/', include(global_param_urls)),
                       url(r'^view/', include(view_urls)),
                       url(r'^user/', include(user_urls)),
                       url(r'^api/', include(api_urls)),
                       url(r'^data_display/', include(data_urls)),
                       url(r'^status.taobao', status_check)
)
