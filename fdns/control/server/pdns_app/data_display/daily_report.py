# -*- coding: utf-8 -*-
__author__ = 'jiahong.ljh'

from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import HttpResponse
import json
import time
import logging
import traceback

import data_model

log = logging.getLogger(__name__)

@csrf_exempt
def get_client_ip_datas(request):
    result_data_list = []
    try:
        start_day = time.strftime("%Y-%m-%d 00:00:00", time.localtime(time.time() - 30*24*60*60))          #一个月
        end_day = time.strftime("%Y-%m-%d 00:00:00", time.localtime(time.time()))
        client_ip_list = data_model.PdnsClientIP.objects.filter(gmt_create__gt=start_day, gmt_create__lte=end_day, ).order_by("gmt_create")
        for client_ip in client_ip_list:
            result_data_list.append({
                "date":client_ip.gmt_create.strftime("%Y%m%d"),
                "client_ip" : client_ip.client_ip,
                "client_real_ip" : client_ip.client_real_ip
            })
        return HttpResponse(json.dumps({"result": result_data_list}))
    except:
        log.error(traceback.format_exc())
        return HttpResponse(json.dumps({"result": [], "msg":"ERROR"}))


@csrf_exempt
def get_total_query_datas(request):
    try:
        result_data_list = []
        start_day = time.strftime("%Y-%m-%d 00:00:00", time.localtime(time.time() - 30*24*60*60))          #一个月
        end_day = time.strftime("%Y-%m-%d 00:00:00", time.localtime(time.time()))
        total_query_list = data_model.PdnsTotalQuery.objects.filter(gmt_create__gt=start_day, gmt_create__lte=end_day, ).order_by("gmt_create")
        for query in total_query_list:
            result_data_list.append({
                "date": query.gmt_create.strftime("%Y%m%d"),
                "cm10" : query.cm10,
                "cm9" : query.cm9,
                "st3" : query.st3
            })
        return HttpResponse(json.dumps({"result": result_data_list}))
    except:
        log.error(traceback.format_exc())
        return HttpResponse(json.dumps({"result": [], "msg":"ERROR"}))

@csrf_exempt
def get_query_type_datas(request):
    try:
        result_data_list = []
        start_day = time.strftime("%Y-%m-%d 00:00:00", time.localtime(time.time() - 24*60*60))          #一天
        end_day = time.strftime("%Y-%m-%d 00:00:00", time.localtime(time.time()))
        query_type_list = data_model.PdnsQueryType.objects.filter(gmt_create__gte=start_day, gmt_create__lt=end_day, ).order_by("q_count")
        for query in query_type_list:
            result_data_list.append({
                "qtype": query.q_type,
                "count" : query.q_count
            })
        return HttpResponse(json.dumps({"result": result_data_list}))
    except:
        log.error(traceback.format_exc())
        return HttpResponse(json.dumps({"result": [], "msg":"ERROR"}))

@csrf_exempt
def get_query_len_datas(request):
    try:
        result_data_list = []
        start_day = time.strftime("%Y-%m-%d 00:00:00", time.localtime(time.time() - 24*60*60))          #一天
        end_day = time.strftime("%Y-%m-%d 00:00:00", time.localtime(time.time()))
        query_len_list = data_model.PdnsQueryLen.objects.filter(gmt_create__gte=start_day, gmt_create__lt=end_day, ).order_by("q_count")
        for query in query_len_list:
            result_data_list.append({
                "qlen": query.q_len,
                "count" : query.q_count
            })
        return HttpResponse(json.dumps({"result": result_data_list}))
    except:
        log.error(traceback.format_exc())
        return HttpResponse(json.dumps({"result": [], "msg":"ERROR"}))

@csrf_exempt
def get_query_label_datas(request):
    try:
        result_data_list = []
        start_day = time.strftime("%Y-%m-%d 00:00:00", time.localtime(time.time() - 24*60*60))          #一天
        end_day = time.strftime("%Y-%m-%d 00:00:00", time.localtime(time.time()))
        query_len_list = data_model.PdnsQueryLabel.objects.filter(gmt_create__gte=start_day, gmt_create__lt=end_day, ).order_by("q_label")
        for query in query_len_list:
            result_data_list.append({
                "qlabel": query.q_label,
                "count" : query.q_count
            })
        return HttpResponse(json.dumps({"result": result_data_list}))
    except:
        log.error(traceback.format_exc())
        return HttpResponse(json.dumps({"result": [], "msg":"ERROR"}))



#
# @csrf_exempt
# def get_rcode_datas(request):
#     result_data_list = []
#     yesterday = time.strftime("%Y%m%d", time.localtime(time.time() - 24*60*60))
#     db_result = MongodbManager.get_time_data_from_mongodb(yesterday, 'Rcode')
#     rcodes_list = db_result.get('rcodes')
#     if rcodes_list is not None:
#         for query_type in rcodes_list:
#             result_data_list.append({
#                 "rcode": query_type.get('rcode'),
#                 "count" : query_type.get('count')
#             })
#     return HttpResponse(json.dumps({"result": result_data_list}))

#
# @csrf_exempt
# def get_rcode_servfail_datas(request):
#     result_data_list = []
#     yesterday = time.strftime("%Y%m%d", time.localtime(time.time() - 24*60*60))
#     db_result = MongodbManager.get_time_data_from_mongodb(yesterday, 'RcodeServFail')
#     rcode_servfails_list = db_result.get('rcode_servfails')
#     if rcode_servfails_list is not None:
#         for query_type in rcode_servfails_list:
#             result_data_list.append({
#                 "qname": query_type.get('qname'),
#                 "count" : query_type.get('count')
#             })
#     return HttpResponse(json.dumps({"result": result_data_list}))
#
#
# @csrf_exempt
# def get_rcode_nxdomain_datas(request):
#     result_data_list = []
#     yesterday = time.strftime("%Y%m%d", time.localtime(time.time() - 24*60*60))
#     db_result = MongodbManager.get_time_data_from_mongodb(yesterday, 'RcodeNxDomain')
#     rcode_nxdomains_list = db_result.get('rcode_nxdomains')
#     if rcode_nxdomains_list is not None:
#         for query_type in rcode_nxdomains_list:
#             result_data_list.append({
#                 "qname": query_type.get('qname'),
#                 "count" : query_type.get('count')
#             })
#     return HttpResponse(json.dumps({"result": result_data_list}))
#
