#coding=utf-8
from django.conf.urls.defaults import patterns

import server_views

urlpatterns = patterns('',
                       (r'^server_menu_tree/$', server_views.server_menu_tree),
                       (r'^pdns_server_manage/$', server_views.pdns_server_manage),
                       (r'^add_pdns_server/$', server_views.add_pdns_server),
                       (r'^delete_pdns_server/$', server_views.delete_pdns_server),
                       (r'^update_pdns_server/$', server_views.update_pdns_server),
                       (r'^pdns_server_list/$', server_views.pdns_server_list),
                       (r'^pdns_server_info/$', server_views.pdns_server_info),
                       (r'^report_server_status/$', server_views.report_server_status),
)
