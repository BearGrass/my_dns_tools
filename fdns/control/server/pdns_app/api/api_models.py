# coding=utf-8
import logging
import socket
import copy
import json
import traceback
import time

from django.db import models

from pdns import utils, error_code, constants

log = logging.getLogger(__name__)

HOSTNAME = socket.gethostname()

class API_APP(models.Model):
    """
    API 权限
    privileges：
    *表示所有权限
    {
    "server_group1":{
        "zone1":["domain1","domain2","domain3"]
        }
    "server_group2":{
        "zone2":"*"
        },
    "server_group3":"*",

    }
    """
    username = models.CharField(max_length=30, unique=True)
    last_name = models.CharField(max_length=30, unique=True)
    password = models.CharField(max_length=128)
    is_superuser = models.IntegerField()

    class Meta:
        db_table = u'auth_user'

class BaseAPI(object):
    appId = None
    appKey = None

    def is_app_exist(self):
        try:
            self.app = utils.get_model_nullable(API_APP, **{"username": self.appId, "password": self.appKey})  # 用户名密码校验
            if self.is_superuser():#间接用来判断app是否存在
                return True
        except:
            log.error(traceback.format_exc())
            raise Exception(error_code.PERMISSION_DENIED)

    def param_validate(self):
        require_fields = self.require_fields
        for field in require_fields:
            value = self.__dict__.get(field.get("name"))
            if field.get("require"):
                if field.get("name") not in self.__dict__:
                    error = copy.deepcopy(error_code.PARAMETER_ERROR)
                    error["message"] = "%s is required" % field.get("name")
                    raise Exception(error)
            else:
                if field.has_key("default") and value is None:
                    self.__dict__[field.get("name")] = value = field.get("default")

            if field.get("name") in self.__dict__:
                if value is not None and type(value) not in field.get("type"):
                    error = copy.deepcopy(error_code.PARAMETER_ERROR)
                    error["message"] = "%s is %s, type :%s required," % (field.get("name"), type(value).__name__,
                                                                         ",".join([t.__name__ for t in field.get("type")]))
                    raise Exception(error)
        return True

    def is_superuser(self):
        return bool(self.app.is_superuser)

class APIAuthority(models.Model):
    """
    IP权限验证数据库表
    """
    ip = models.CharField(max_length=255)
    bu = models.CharField(max_length=255)       # 所属事业部,预留
    product = models.CharField(max_length=255)  # 所属产品线,预留

    class Meta:
        db_table = u'ip_white_list'

    @staticmethod
    def verify_authority(request):
        """
        根据源IP验证用户操作权限
        """
        cip = utils.get_client_ip(request)
        if None != cip:
            try:
                res = APIAuthority.objects.filter(ip=cip)
            except:
                log.error("api ip authority database select failed!")
                raise Exception(error_code.DB_ACTION_FAILED)
            if len(res) > 0:
                log.info("client ip[%s] is in white list" % str(cip))
                return cip
        # FIXME
        # 此时（源ip不在白名单中）理论上应该将抛异常,说明对应ip没有访问权限
        # 为了防止刚上线时有ip没加全,暂时输出日志,不抛异常
        log.error("client ip[%s] is not in white list" % str(cip))
        #raise Exception(error_code.APP_USER_NO_AUTH)
        return cip

class ADMSTask(models.Model):
    """
    ADMS任务数据库表
    """
    appId = models.CharField(max_length=255)
    appKey = models.CharField(max_length=255)
    zone = models.CharField(max_length=255)
    api = models.CharField(max_length=255)
    uuid = models.CharField(max_length=255)
    data = models.CharField(max_length=65535)
    s_time = models.DateTimeField(auto_now_add=True)
    e_time = models.DateTimeField(default="1000-01-01 00:00:00")
    status = models.CharField(max_length=64)
    pdns_sync_status = models.IntegerField(null=True, blank=True)

    class Meta:
        db_table = u'adms_task'

    @staticmethod
    def update_taskdb_status(myuuid, status):
        """
        更新任务数据库表中的状态status字段，用来标识目前任务的执行状态
        """
        try:
            log.info("update task [uuid : %s] status : %s" % (myuuid, status))
            tasks = ADMSTask.objects.filter(uuid=myuuid)
            for task in tasks:
                task.status = status
                task.e_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                task.save()
        except:
            log.error("update taskdb status except : %s" % traceback.format_exc())

class DELETE_RECORD(BaseAPI):
    """
    删除record
    """
    def __init__(self, **args):
        self.api = None
        self.uuid = None

        self.require_fields = [
            {"name": "appId", "type": (unicode, str), "require": True},
            {"name": "appKey", "type": (unicode, str), "require": True},
            {"name": "zone", "type": (unicode, str), "require": True},
            {"name": "api", "type": (unicode, str), "require": True},
            {"name": "uuid", "type": (unicode, str), "require": False, "default": ""},
            {"name": "data", "type": (list,), "require": True}
        ]

        for key, value in args.items():
            self.__dict__[key] = value
        self.param_validate()
        self.is_app_exist()
        self.format_full_zone_name()
        self.set_datas()

    def set_datas(self):
        for name in self.data:
            domain_name = self.format_full_domain_name(name)
            self.write_to_taskdb(domain_name)

    def format_full_domain_name(self, domain_name):
        if str(domain_name).endswith("."):
            if str(domain_name).endswith(self.zone):
                return domain_name
            else:
                raise Exception(error_code.DOMAIN_NAME_ERROR)
        else:
            if "@" == domain_name or "" == domain_name:
                return self.zone
            elif domain_name:
                return "%s.%s" % (domain_name, self.zone)
            else:
                return self.zone

    def write_to_taskdb(self, name=None):
        """
        将API接收到的任务写入任务数据库，作用：
        """
        try:
            data = {}
            data["name"] = name
            data_str = json.dumps(data)
            task = ADMSTask(appId=self.appId, appKey=self.appKey, zone=self.zone, api=self.api, uuid=self.uuid, data=data_str, pdns_sync_status=constants.PDNS_SYNC_STAUS_INIT, status='000000')
            task.save()
        except:
            log.error("operate database except : %s" % traceback.format_exc())
            raise Exception(error_code.DB_ACTION_FAILED)

    def format_full_zone_name(self):
        self.zone = str(self.zone).rstrip(".") + "."


class CONFIG_API_APP(BaseAPI):
    appId = None
    appKey = None
    config_app_id = None

    def __init__(self, **args):
        self.superuser = 0
        self.require_fields = [
            {"name": "appId", "type": (unicode, str), "require": True},
            {"name": "appKey", "type": (unicode, str), "require": True},
            {"name": "superuser", "type": (int,), "require": False, "default": 0},
            {"name": "config_app_id", "type": (unicode, str), "require": True},
        ]
        for (key, value) in args.items():
            self.__dict__[key] = value
        self.validate()

    def is_appid_exist(self):
        app = utils.get_model_nullable(API_APP, **{"username": self.config_app_id})
        self.app_object = app
        return bool(app)

    def add_app_object(self):
        add_app = API_APP(username=self.config_app_id, is_superuser=self.superuser)
        return add_app

    def validate(self):
        self.param_validate()
        return self.is_app_exist()            # superuser校验：在具体操作中有校验。如：APP_Manager.delete_app_user()中