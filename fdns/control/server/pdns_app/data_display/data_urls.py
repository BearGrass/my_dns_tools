# -*- coding: utf-8 -*-
__author__ = 'pinghua.wph'
# from django.conf.urls.defaults import patterns
from django.conf.urls import patterns

import data_views
import daily_report
# from ext_domain_attack import *
# from DN_attack_conf import local_dns_DN_attack, edit_datas

urlpatterns = patterns('',
    (r'^data_menu_tree/$', data_views.data_menu_tree),
    (r'^get_forward_data_list/$', data_views.get_forward_data_list),

    # Daily Reports
    (r'^daily_report', data_views.daily_report),
    (r'^get_client_ip_datas', daily_report.get_client_ip_datas),
    (r'^get_total_query_datas', daily_report.get_total_query_datas),
    (r'^get_query_type_datas', daily_report.get_query_type_datas),
    (r'^get_query_len_datas', daily_report.get_query_len_datas),
    (r'^get_query_label_datas', daily_report.get_query_label_datas),

    # (r'^get_rcode_datas', daily_report.get_rcode_datas),
    # (r'^get_rcode_servfail_datas', daily_report.get_rcode_servfail_datas),
    # (r'^get_rcode_nxdomain_datas', daily_report.get_rcode_nxdomain_datas),
    #
    # # qps
    # (r'^qps_graph_view$', qps_graph_view),
    # (r'^get_qps_datas', get_qps_datas),
    # (r'^get_min_avg_qps_datas', get_min_avg_qps_datas),
    #
    # # rt
    # (r'^rt_graph_view$', rt_graph_view),
    # (r'^get_rt_datas$', get_rt_datas),
    #
    # request
    (r'^request_graph_view$', data_views.request_graph_view),
    (r'^get_request_datas$', data_views.get_request_datas),
    #
    # drop
    (r'^drop_graph_view$', data_views.drop_graph_view),
    (r'^get_drop_datas$', data_views.get_drop_datas),

    # prefetch
    (r'^prefetch_graph_view$', data_views.prefetch_graph_view),
    (r'^get_prefetch_datas$', data_views.get_prefetch_datas),

    # view
    (r'^view_graph_view$', data_views.view_graph_view),
    (r'^get_view_list$', data_views.get_view_list),
    (r'^get_view_datas$', data_views.get_view_datas),

    # view detail
    (r'^view_detail_table_view$', data_views.view_detail_table_view),
    (r'^get_view_detail_datas$', data_views.get_view_detail_datas),

    #
    # # topn
    # (r'^topn_graph_view$', topn_graph_view),
    # (r'^get_topn_datas$', get_topn_datas),
    # (r'^get_topn_ma_datas$', get_topn_ma_datas),
    #

    #
    # # conf配置
    # (r'^conf/DN_attack$', local_dns_DN_attack),
    # (r'^conf/edit_datas$', edit_datas),

)