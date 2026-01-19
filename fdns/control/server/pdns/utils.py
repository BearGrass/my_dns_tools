# coding=utf-8
import datetime
import json
import re
import uuid
import hashlib
import time
import requests


from django.db.models.base import ModelState
from django.core.paginator import Paginator
from django.db.models import Model

from pdns import constants


def dict_strip(dc):
    for k in dc:
        if type(dc[k]) == str or type(dc[k]) == unicode:
            dc[k] = dc[k].strip()


def dict_to_model(dc, cls):
    obj = cls.__new__(cls)
    obj.__dict__ = dc
    obj._state = ModelState()
    return obj


def model_to_dict(obj):
    if obj:
        src_dict = obj.__dict__
        key_list = dir(obj)
        result = {}
        for key in key_list:
            try:
                k_value = getattr(obj, key)
            except:
                continue
            if len(key)==0 or "_"==key[0]:
                continue
            if False == src_dict.has_key(key):
                if isinstance(k_value, Model):
                    result[key] = k_value
            else:
                result[key] = k_value
        return result
    else:
        return {}


def models_to_dicts(model_list):
    dict_list = []
    for model in model_list:
        dict_list.append(model_to_dict(model))
    return dict_list


def change_model_related_to_dict(obj):
    if obj:
        src_dict = obj.__dict__
        key_list = dir(obj)
        result = {}
        for key in key_list:
            try:
                k_value = getattr(obj, key)
            except:
                continue
            if len(key)==0 or "_"==key[0]:
                continue
            if False == src_dict.has_key(key):
                if isinstance(k_value, Model):
                    result[key] = change_model_related_to_dict(k_value)
            else:
                if isinstance(k_value, Model):
                    result[key] = change_model_related_to_dict(k_value)
                else:
                    result[key] = k_value
        return result
    else:
        return {}


#分页工具
#object_list 查询结果
#page_num 当前页
#page_size 每页的结果数,默认为 constants里面的配置
#RETURN_DICT 是否返回字典格式,默认为是,否则返回对象数组
def page_utils(object_list, page_num, page_size=constants.BASE_PAGE_SIZE, RETURN_DICT=True):
    paginator = Paginator(object_list, page_size)
    if RETURN_DICT:
        result = []
        for obj in paginator.page(page_num):
            result.append(change_model_related_to_dict(obj))
        return result, paginator
    else:
        return paginator.page(page_num), paginator


#json handler
#解决时间解析问题
def default_json_hanlder(obj):
    if isinstance(obj, datetime.datetime):
        return obj.ctime()
    else:
        return json.JSONEncoder().default(obj)


def get_model_result(model, *orders, **wheres):
    """
    使用动态条件的方式查询结果
    :param model: 查询的对象
    :param orders: 指定排序方式
    :param wheres: 查询条件
    使用方式1：
        get_model_result(Article,’-createtime’,username='aaa')
    使用方式2:
        kwargs = {}
        kwargs['username'] = 'aaa'
        get_model_result(model,  **kwargs)
    """
    ret = model.objects
    ret = ret.filter(**wheres)
    for order in orders:
        ret = ret.order_by(order)
    return ret


def get_dict_result(model, *orders, **wheres):
    """
    获取结果为dict
    """
    dict_result = []
    for model in get_model_result(model, *orders, **wheres):
        dict_result.append(model_to_dict(model))
    return dict_result


def check_ip(ip):
    """
    正则判断IP是否合法
    """
    if ip is None:
        return False
    return re.match('^(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])$', ip)


def get_model_nullable(model, select_related=False, **kwargs):
    '''
    查询MODEL,如果没有的话返回NONE
    '''
    try:
        if select_related:
            return model.objects.select_related().get(**kwargs)
        else:
            return model.objects.get(**kwargs)
    except model.DoesNotExist:
        return None


def unique(old_list):
    """
    数组去重
    """
    newList = []
    for x in old_list:
        if x not in newList:
            newList.append(x)
    return newList


def gen_uuid():
    return uuid.uuid1().hex


def is_ip_string(ip_string):
    return re.match("((2[0-4]\d|25[0-5]|[01]?\d\d?)\.){3}(2[0-4]\d|25[0-5]|[01]?\d\d?)", ip_string)

def md5_encode(string):
    return hashlib.md5(string).hexdigest().upper()


def get_client_ip(request):
    try:
        if request.META.has_key('HTTP_X_FORWARDED_FOR'):
            cip = request.META['HTTP_X_FORWARDED_FOR']
        else:
            cip = request.META['REMOTE_ADDR']
        return cip
    except:
        return None


def time_from_sec_to_str(time_sec):
    '''
    FUNC:把时间从时间戳转成字符串
    '''
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time_sec))

def time_from_str_to_sec(time_str):
    '''
    FUNC:把时间从字符串转成时间戳
    '''
    return int(time.mktime(time.strptime(time_str, '%Y-%m-%d %H:%M:%S')))

def get_data_from_ots(url, payload):
    data_list = []
    res = requests.get(url, params=payload)
    result = json.loads(res.text)
    if result.has_key('data'):
        data_list = result['data']
    return data_list


def add_data_to_series(stime_str, etime_str, db_data, lines_name_list, granularity):
    '''
    db_data=[
        {line_a:1, line_2:3, line_3:100, ...,_collectDate:time_ms, _time:time_str},
        {line_a:1, line_2:3, line_3:100, ...,_collectDate:time_ms, _time:time_str},
        ...
    ]
    return：对于1s以上的数据，lines_data_list:
    [
        [[x,y],[x,y],...],
        [[x,y],[x,y],...]
        ...
    ]
    '''
    lines_data_list = [[] for line in lines_name_list]
    lines_number = len(lines_name_list)
    stime_sec = time_from_str_to_sec(stime_str)
    etime_sec = time_from_str_to_sec(etime_str)

    # 整理数据，并且给线条没有的点补充None点
    for data in db_data:
        if False == data.has_key("timeStamp"):
            continue

        data_time = int(data["timeStamp"])/1000
        if  data_time <= etime_sec and data_time >= stime_sec:
            # 对于每条数据都判断这条数据前有多少空白，用while循环补上空白
            for j in range(lines_number):
                if data.has_key(lines_name_list[j]['name_en']):
                    try:
                        lines_data_list[j].append([data["time"], int(data[lines_name_list[j]['name_en']])])
                    except:
                        # 过滤时间参数
                        continue
                else:
                    lines_data_list[j].append([data["time"], None])

    return lines_data_list


def time_interval_judgment(datetimepicker_start_sec, datetimepicker_end_sec):
    '''
    FUNC:判断时间区间的长短
    RETURN:返回'1s','1m','5m','1h'几种粒度
    '''
    # time_interval = 1800                                # 间隔小于1800个点
    one_sec_interval = 30*60                            # 秒级时间间隔:30min
    one_min_interval = 24*60*60                         # 分钟级时间间隔:1day
    five_min_interval = 5*24*60*60                      # 5分钟级时间间隔:5day
    one_hour_interval = 30*24*60*60                     # 1小时级时间间隔:1个月
    time_now_sec = int(time.time())                          # 获取现在格林威治时间，单位为秒 float
    time_one_month_ago_sec = time_now_sec - (30*24*60*60)     # (30天*24时*60分*60秒)=2592000秒，一个月前的时间点，用来判断是否要给秒级数据。
    time_interval_one_sec = datetimepicker_end_sec - datetimepicker_start_sec
    arithmetic_result = '1min'
    if datetimepicker_start_sec >= time_one_month_ago_sec:
        # start_time在一个月前的右边
        if time_interval_one_sec <= one_sec_interval:
            # get data from one_sec database
            arithmetic_result = '1s'
        elif time_interval_one_sec <= one_min_interval:
            arithmetic_result = '1min'
        elif time_interval_one_sec <= five_min_interval:
            arithmetic_result = '5min'
        elif time_interval_one_sec <= one_hour_interval:
            arithmetic_result = '1h'
        else:
            arithmetic_result = '1d'
    else:
        # get data from one_min,five_min,one_hour database
        if time_interval_one_sec <= one_min_interval:
            arithmetic_result = '1m'
        elif time_interval_one_sec <= five_min_interval:
            arithmetic_result = '5m'
        elif time_interval_one_sec <= one_hour_interval:
            arithmetic_result = '1h'
        else:
            arithmetic_result = '1d'
    return arithmetic_result

def md5sum(text):
    m = hashlib.md5()
    m.update(text)
    return m.hexdigest()

def auth_data(time, key):
    auth_data = md5sum(str(time) + key)
    return auth_data

def gen_auth_data(auth_user, key):
    time_now = str(int(time.time() * 1000))
    md5_check_sum = auth_data(time_now, key)
    return {
        "user": auth_user,
        "time": time_now,
        "auth": md5_check_sum
    }