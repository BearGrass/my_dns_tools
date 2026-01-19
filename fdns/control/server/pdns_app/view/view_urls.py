#coding=utf-8
from django.conf.urls.defaults import patterns

from view_views import *

urlpatterns = patterns('',
    (r'view_menu_tree/$', view_menu_tree),
     (r'^view_page/$', view_page),
    #得到view列表
    (r'^view_list/$', view_list),
    #增加一个view
    (r'^add_view/$', add_view),
    #删除一个view
    (r'^delete_view/$', delete_view),
    #更新一个view
    (r'^update_view/$', update_view),
    #得到一个view的信息
    (r'^view_info/$', get_view),
)



