#coding=utf8

import json
import time
import random
import logging
import traceback
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render_to_response
from django.template.context import RequestContext
from django.shortcuts import HttpResponse
from django.contrib.auth.decorators import login_required
from rest_framework.parsers import JSONParser

import settings
from pdns.mythread import MyThread
from pdns import error_code, constants, utils
from pdns_app.server.server_model import PdnsServer
from pdns_app.view.view_models import View

log = logging.getLogger(__name__)




@login_required
def data_menu_tree(request):
    children = [
        {'id': 'daily-report-graph', 'text': '日报', 'leaf': True},
        {'id': 'request-graph', 'text': 'REQUEST曲线', 'leaf': True},
        {'id': 'drop-graph', 'text': 'DROP曲线', 'leaf': True},
        {'id': 'prefetch-graph', 'text': 'PREFETCH曲线', 'leaf': True},
        {'id': 'view-graph', 'text': 'VIEW曲线', 'leaf': True},
        {'id': 'view-detail-table', 'text': 'VIEW DETAIL表格', 'leaf': True}
        # {'id': 'qps-graph', 'text': 'QPS曲线', 'leaf': True},
        # {'id': 'rt-graph', 'text': 'RT曲线', 'leaf': True},
        # {'id': 'topn-graph', 'text': 'TOP-N曲线', 'leaf': True},



    ]
    tree = {'id': '0', 'children': children}
    json_tree = json.dumps(tree)
    return HttpResponse(json_tree)

@csrf_exempt
def get_forward_data_list(request):
    try:
        server_dic_list = []
        forward_server_list = PdnsServer.objects.filter(type=constants.SERVER_TYPE_FWD)
        for fwd in forward_server_list:
            server_dic_list.append({"name": fwd.host})

        # TODO forward 机器所在机房信息，应该从host的后缀获取
        server_dic_list.append({"name": "cm9"})
        server_dic_list.append({"name": "cm10"})
        server_dic_list.append({"name": "st3"})
        server_dic_list.append({"name": "all"})
        return HttpResponse(json.dumps({"result": server_dic_list}))

    except:
        log.error(traceback.format_exc())
        return HttpResponse(json.dumps({"result": [], "msg":"ERROR"}))


@login_required
@csrf_exempt
def daily_report(request):
    args = RequestContext(request)
    return render_to_response("data_display/daily_report.html", args)


@csrf_exempt
@login_required
def qps_graph_view(request):
    args = RequestContext(request)
    series_name_list_str = ""
    for key_value_dic in constants.QPS_EN_CH_MAP:
        series_name_list_str += key_value_dic['name_cn'] + "_"
    args['SERIES_NAME'] = series_name_list_str.rstrip('_')
    args['DATA_YESTERDAY'] = utils.time_from_sec_to_str(int(time.time()) - 24*60*60)[:-9]
    return render_to_response("data_display/local_dns_qps.html", args)


@login_required
@csrf_exempt
def request_graph_view(request):
    args = RequestContext(request)
    series_name_list_str = ""
    for key_value_dic in constants.REQUEST_EN_CH_MAP:
        series_name_list_str += key_value_dic['name_cn'] + "_"
    args['SERIES_NAME'] = series_name_list_str.rstrip('_')
    return render_to_response("data_display/request.html", args)


@login_required
@csrf_exempt
def drop_graph_view(request):
    args = RequestContext(request)
    series_name_list_str = ""
    for key_value_dic in constants.DROP_EN_CH_MAP:
        series_name_list_str += key_value_dic['name_cn'] + "_"
    args['SERIES_NAME'] = series_name_list_str.rstrip('_')
    return render_to_response("data_display/request_drop.html", args)


@login_required
@csrf_exempt
def prefetch_graph_view(request):
    args = RequestContext(request)
    series_name_list_str = ""
    for key_value_dic in constants.PREFETCH_EN_CH_MAP:
        series_name_list_str += key_value_dic['name_cn'] + "_"
    args['SERIES_NAME'] = series_name_list_str.rstrip('_')
    return render_to_response("data_display/prefetch.html", args)


@login_required
@csrf_exempt
def view_graph_view(request):
    args = RequestContext(request)
    series_name_list_str = ""
    for key_value_dic in constants.VIEW_EN_CH_MAP:
        series_name_list_str += key_value_dic['name_cn'] + "_"
    args['SERIES_NAME'] = series_name_list_str.rstrip('_')
    return render_to_response("data_display/ldns_view.html", args)


@login_required
@csrf_exempt
def rt_graph_view(request):
    args = RequestContext(request)
    return render_to_response("data_display/local_dns_rt.html", args)


@login_required
@csrf_exempt
def topn_graph_view(request):
    args = RequestContext(request)
    series_name_list_str = ""
    for key_value_dic in constants.TOPN_MA_EN_CH_MAP:
        series_name_list_str += key_value_dic['name_cn'] + "_"
    args['SERIES_NAME'] = series_name_list_str.rstrip('_')
    return render_to_response("data_display/local_dns_topn.html", args)


@csrf_exempt
@login_required
def view_detail_table_view(request):
    args = RequestContext(request)
    series_name_list_str = ""
    for key_value_dic in constants.VIEW_EN_CH_MAP:
        series_name_list_str += key_value_dic['name_cn'] + "_"
    args['SERIES_NAME'] = series_name_list_str.rstrip('_')
    return render_to_response("data_display/view_detail.html", args)


@csrf_exempt
@login_required
def get_request_datas(request):
    if request.method == 'POST':
        try:
            request_info = JSONParser().parse(request)
            start_time = request_info.get('start_time', None)
            end_time = request_info.get('end_time', None)
            server_name = request_info.get('server')
            # merge_algorithm = request_info.get('merge_algorithm')

            if start_time is None or end_time is None:
                now = int(time.time())
                start_time = time.strftime("%Y-%m-%d %H:%M:00", time.localtime(now-24*60*60))
                end_time = time.strftime("%Y-%m-%d %H:%M:00", time.localtime(now))

            granularity = utils.time_interval_judgment(utils.time_from_str_to_sec(start_time), utils.time_from_str_to_sec(end_time))
            if granularity == '1s':                 # 没有秒级数据
                granularity = '1min'

            if server_name in ["", None, "all"]:
                data_key = "%sPDNS_REQUEST" % granularity
            else:
                data_key = "%sPDNS_REQUEST%s" % (granularity, server_name)

            url = "http://%s/api/otsGetRange.do" % settings.OTS_HOST
            payload = {
                "dataSpace":"PDNS",
                "dataKey":data_key,
                "startTime":start_time,
                "endTime":end_time
            }
            auth = utils.gen_auth_data("ADNS", "adns")
            payload.update(auth)
            db_datas = utils.get_data_from_ots(url, payload)
            series_datas = utils.add_data_to_series(start_time, end_time, db_datas, constants.REQUEST_EN_CH_MAP, granularity)
            #print series_datas
            return HttpResponse(json.dumps({"result": series_datas}))

        except Exception as e:
            log.error(traceback.format_exc())
            return HttpResponse(json.dumps({"result":[], "msg": "get_request_datas error"}))


@csrf_exempt
@login_required
def get_drop_datas(request):
    if request.method == 'POST':
        try:
            request_info = JSONParser().parse(request)
            start_time = request_info.get('start_time', None)
            end_time = request_info.get('end_time', None)
            server_name = request_info.get('server')
            # merge_algorithm = request_info.get('merge_algorithm')

            if start_time is None or end_time is None:
                now = int(time.time())
                start_time = time.strftime("%Y-%m-%d %H:%M:00", time.localtime(now-24*60*60))
                end_time = time.strftime("%Y-%m-%d %H:%M:00", time.localtime(now))

            granularity = utils.time_interval_judgment(utils.time_from_str_to_sec(start_time), utils.time_from_str_to_sec(end_time))
            if granularity == '1s':                 # 没有秒级数据
                granularity = '1min'

            # data_key = "1minPDNS_DROP_forwarder01.pdns.cm9"
            if server_name in ["", None, "all"]:
                data_key = "%sPDNS_DROP" % granularity
            else:
                data_key = "%sPDNS_DROP%s" % (granularity, server_name)

            url = "http://%s/api/otsGetRange.do" % settings.OTS_HOST
            payload = {
                "dataSpace":"PDNS",
                "dataKey":data_key,
                "startTime":start_time,
                "endTime":end_time
            }
            auth = utils.gen_auth_data("ADNS", "adns")
            payload.update(auth)
            db_datas = utils.get_data_from_ots(url, payload)
            series_datas = utils.add_data_to_series(start_time, end_time, db_datas, constants.DROP_EN_CH_MAP, granularity)
            #print series_datas
            return HttpResponse(json.dumps({"result": series_datas}))

        except:
            log.error(traceback.format_exc())
            return HttpResponse(json.dumps({"result":[], "msg": "get_drop_datas error"}))


@csrf_exempt
@login_required
def get_prefetch_datas(request):
    if request.method == 'POST':
        try:
            request_info = JSONParser().parse(request)
            start_time = request_info.get('start_time', None)
            end_time = request_info.get('end_time', None)
            server_name = request_info.get('server')
            # merge_algorithm = request_info.get('merge_algorithm')

            if start_time is None or end_time is None:
                now = int(time.time())
                start_time = time.strftime("%Y-%m-%d %H:%M:00", time.localtime(now-24*60*60))
                end_time = time.strftime("%Y-%m-%d %H:%M:00", time.localtime(now))

            granularity = utils.time_interval_judgment(utils.time_from_str_to_sec(start_time), utils.time_from_str_to_sec(end_time))
            if granularity == '1s':                 # 没有秒级数据
                granularity = '1min'

            # data_key = "1minPDNS_DROP_forwarder01.pdns.cm9"
            if server_name in ["", None, "all"]:
                data_key = "%sPDNS_PREFETCH" % granularity
            else:
                data_key = "%sPDNS_PREFETCH%s" % (granularity, server_name)

            url = "http://%s/api/otsGetRange.do" % settings.OTS_HOST
            payload = {
                "dataSpace":"PDNS",
                "dataKey":data_key,
                "startTime":start_time,
                "endTime":end_time
            }
            auth = utils.gen_auth_data("ADNS", "adns")
            payload.update(auth)
            db_datas = utils.get_data_from_ots(url, payload)
            series_datas = utils.add_data_to_series(start_time, end_time, db_datas, constants.PREFETCH_EN_CH_MAP, granularity)
            #print series_datas
            return HttpResponse(json.dumps({"result": series_datas}))
        except Exception as e:
            log.error(traceback.format_exc())
            return HttpResponse(json.dumps({"result":[], "msg": "get_prefetch_datas error"}))


@csrf_exempt
@login_required
def get_view_datas(request):
    if request.method == 'POST':
        try:
            request_info = JSONParser().parse(request)
            start_time = request_info.get('start_time', None)
            end_time = request_info.get('end_time', None)
            server_name = request_info.get('server', "all")
            view_name = request_info.get('view_name', "default")
            # merge_algorithm = request_info.get('merge_algorithm')

            if start_time is None or end_time is None:
                now = int(time.time())
                start_time = time.strftime("%Y-%m-%d %H:%M:00", time.localtime(now-6*60*60))
                end_time = time.strftime("%Y-%m-%d %H:%M:00", time.localtime(now))

            granularity = utils.time_interval_judgment(utils.time_from_str_to_sec(start_time), utils.time_from_str_to_sec(end_time))
            if granularity == '1s':                 # 没有秒级数据
                granularity = '1min'

            # data_key = "1minPDNS_DROP_forwarder01.pdns.cm9"
            if server_name in ["", None, "all"]:
                data_key = "%sPDNS_VIEW%s" % (granularity, view_name)
            else:
                data_key = "%sPDNS_VIEW%s%s" % (granularity, view_name, server_name)

            url = "http://%s/api/otsGetRange.do" % settings.OTS_HOST
            payload = {
                "dataSpace":"PDNS",
                "dataKey":data_key,
                "startTime":start_time,
                "endTime":end_time
            }
            auth = utils.gen_auth_data("ADNS", "adns")
            payload.update(auth)
            db_datas = utils.get_data_from_ots(url, payload)
            series_datas = utils.add_data_to_series(start_time, end_time, db_datas, constants.VIEW_EN_CH_MAP, granularity)
            #print series_datas
            return HttpResponse(json.dumps({"result": series_datas}))
        except Exception as e:
            log.error(traceback.format_exc())
            return HttpResponse(json.dumps({"result":[], "msg": "get_view_datas error"}))


@csrf_exempt
@login_required
def get_qps_datas(request):
    if request.method == 'POST':
        try:
            request_info = JSONParser().parse(request)
            print request_info
            stime_str = request_info.get('start_time', None)
            etime_str = request_info.get('end_time', None)
            merge_algorithm = request_info.get('merge_algorithm')

            if stime_str is None or etime_str is None:
                etime_sec = int(time.time())
                stime_sec = etime_sec - 30*60            # 30分钟
                granularity = "1s"
            else:
                etime_sec = utils.time_from_str_to_sec(etime_str)
                stime_sec = utils.time_from_str_to_sec(stime_str)
                granularity = utils.time_interval_judgment(stime_sec, etime_sec)

            key_of_request = 'dns_qps_' + granularity
            db_datas = utils.get_datas_from_hbase(stime_sec, etime_sec, key_of_request)
            series_datas = utils.add_data_to_series(stime_sec, etime_sec, db_datas, constants.QPS_EN_CH_MAP, granularity)
            #print series_datas
            return HttpResponse(json.dumps({"result": series_datas}))

        except Exception as e:
            log.error(traceback.format_exc())
            return HttpResponse(json.dumps({"error": e.message}))


@csrf_exempt
@login_required
def get_topn_ma_datas(request):
    try:
        if request.method != 'POST':
            raise Exception(error_code.UNSUPPORT_METHOD)
        request_info = JSONParser().parse(request)
        print request_info
        data_time = request_info.get('data_time', None)
        domain_level = request_info.get('domain_level', None)
        topn_level = request_info.get('top_level', None)
        granularity = '1m'
        if data_time is None:
            etime_sec = int(time.time())
        else:
            etime_sec = utils.time_from_str_to_sec(data_time)
        stime_sec = etime_sec - 60*60*24        # 1 day

        key_of_topn_with_ma = 'dns_topn_len' + domain_level[-1] + '_' + topn_level + '_' + granularity
        db_datas_list = utils.get_datas_from_hbase(stime_sec, etime_sec, key_of_topn_with_ma)
        series_datas = [[], []]
        series_datas_count = series_datas[0]
        series_datas_ma = series_datas[1]
        domain_name_dict = {}
        for db_data in db_datas_list:
            series_datas_count.append([db_data['_collectDate'], int(db_data['Count'])])
            series_datas_ma.append([db_data['_collectDate'], float(db_data['MA'])])
            domain_name_dict[str(db_data['_collectDate'])] = db_data['Domain']
        return HttpResponse(json.dumps({"result": series_datas, 'domain_name_dict': domain_name_dict}))
    except Exception as e:
        log.error(traceback.format_exc())
        return HttpResponse(json.dumps({"error": e.message}))


@csrf_exempt
def get_view_list(request):
    try:
        view_list = []
        view_objects_list = View.objects.all()
        for view in view_objects_list:
            view_list.append(view.name)

        return HttpResponse(json.dumps({"result": view_list}))
    except:
        log.error(traceback.format_exc())
        return HttpResponse(json.dumps({"result":["default"], "msg": "get_view_list error"}))



@csrf_exempt
def get_view_detail_datas(request):
    THREAD_COUNT = 10
    view_list_dis = []
    lines_name_list = [lines_name['name_en'] for lines_name in constants.VIEW_EN_CH_MAP]

    result = {}
    def do_send(view_list, result, server_name):
        try:
            now = int(time.time())
            start_time = time.strftime("%Y-%m-%d %H:%M:00", time.localtime(now-300))
            end_time = time.strftime("%Y-%m-%d %H:%M:00", time.localtime(now))
            for view in view_list:
                data_key = "1minPDNS_VIEW%s%s" % (view.name, server_name)

                url = "http://%s/api/otsGetRange.do" % settings.OTS_HOST
                payload = {
                    "dataSpace":"PDNS",
                    "dataKey":data_key,
                    "startTime":start_time,
                    "endTime":end_time
                }
                auth = utils.gen_auth_data("ADNS", "adns")
                payload.update(auth)
                db_datas = utils.get_data_from_ots(url, payload)
                if 0 == len(db_datas):
                    result[view.name] = None
                else:
                    result[view.name] = db_datas[-1]
        except:
            log.error(traceback.format_exc())
            return None

    if request.method == 'GET':
        try:
            server_name = request.GET.get('server_name')
            if server_name in ["", None, "all"]:
                server_name = ""

            view_list = View.objects.all()
            index = 0
            for view in view_list:
                if index < THREAD_COUNT:
                    view_list_dis.append([])
                view_list_dis[index%THREAD_COUNT].append(view)
                index +=1

            g_func_list = []
            mt = MyThread()
            for i in range(len(view_list_dis)):
                g_func_list.append({"func":do_send, "args":(view_list_dis[i], result, server_name)})
            mt.set_thread_func_list(g_func_list)
            mt.start()

            series_datas = []
            for key in result.keys():
                row_datas = {
                    "view_name": key,
                    "backup_view": ''
                }
                view_data = result[key]
                for lines_name_meta in lines_name_list:
                    if None == view_data:
                        row_datas[lines_name_meta] = None
                    else:
                        row_datas[lines_name_meta] = view_data[lines_name_meta]
                series_datas.append(row_datas)
            return HttpResponse(json.dumps({"result": series_datas}))
        except Exception as e:
            log.error(traceback.format_exc())
            return HttpResponse(json.dumps({"result":[], "msg": "get_view_detail_datas error"}))


