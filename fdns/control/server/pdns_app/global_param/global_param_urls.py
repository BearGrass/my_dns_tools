#coding=utf-8
from django.conf.urls import *
from global_param_views import *

urlpatterns = patterns('',
    url(r'^global_param/$', global_param),
    url(r'^global_param_menu_tree/$', global_param_menu_tree),
    url(r'^global_param_list/$', global_param_list),
    url(r'^delete_global_param/$', delete_global_param),
    url(r'^update_global_param/$', update_global_param),
    url(r'^add_global_param/$', add_global_param),
)

