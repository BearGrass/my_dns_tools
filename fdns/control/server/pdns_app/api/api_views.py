#coding=utf-8
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

import logging
import time

from django.views.decorators.csrf import csrf_exempt
from rest_framework.parsers import JSONParser
from django.http import HttpResponse

from pdns import utils, error_code
from api_manager import APP_Manager
from api_models import *

log = logging.getLogger(__name__)

class JSONResponse(HttpResponse):
    """
    An HttpResponse that renders its content into JSON.
    """
    def __init__(self, data, log_output=True, **kwargs):
        if "result" in data:
            if data.get("result") == "SUCCESS":
                data["resultCode"] = "000000"
                data["resultMessage"] = "ok"
            else:
                data["resultCode"] = data.get("result")
        if "message" in data:
            data["resultMessage"] = data.get("message")
            del data["message"]
        try:
            content = json.dumps(data, ensure_ascii=False, indent=3)
        except:
            log.error(traceback.format_exc())
            content = json.dumps({"resultCode": "999999", "resultMessage": "Unkown Error"}, ensure_ascii=False,
                                 indent=3)
        if log_output:
            log.info("time:%s, enter|leave api response content:%s" % (int(time.time()*1000), content))
        kwargs['content_type'] = 'application/json'
        super(JSONResponse, self).__init__(content, **kwargs)

@csrf_exempt
def delete_record(request):
    log.info("time:%s, enter|leave api for rr/delRr" % int(time.time()*1000))
    if request.method == "POST":
        myuuid = utils.gen_uuid()
        try:
            record_info = JSONParser().parse(request)
            cip = APIAuthority.verify_authority(request)
            log.info("user[%s] request data:%s" % (str(cip), str(record_info)))
            record_info["api"] = "delRr"
            record_info["uuid"] = myuuid
            DELETE_RECORD(**record_info)
            ADMSTask.update_taskdb_status(myuuid, error_code.DB_SUCCESS_STATUS["result"])
            return JSONResponse({"result": "SUCCESS"})
        except Exception, e:
            log.error(traceback.format_exc())
            # 更新任务执行状态
            try:
                status = e.args[0]["result"]
            except:
                status = error_code.UNKNOWN_FAILED["result"]
            ADMSTask.update_taskdb_status(myuuid, status)
            return JSONResponse(e.args[0], status=200)

@csrf_exempt
def add_app_user(request):
    log.info("time:%s, enter|leave api for app_user/add_app_user" % int(time.time()*1000))
    if request.method == "POST":
        try:
            app_info = JSONParser().parse(request)
            log.info("user request data:%s" % str(app_info))
            app = CONFIG_API_APP(**app_info)
            add_app = APP_Manager.add_app_user(app)
            log.info(app_info)
            return JSONResponse({"result": "SUCCESS", "app": add_app})
        except Exception, e:
            log.error(traceback.format_exc())
            return JSONResponse(e.args[0], status=200)

@csrf_exempt
def delete_app_user(request):
    log.info("time:%s, enter|leave api for app_user/delete_app_user" % int(time.time()*1000))
    if request.method == "POST":
        try:
            app_info = JSONParser().parse(request)
            log.info("user request data:%s" % str(app_info))
            app = CONFIG_API_APP(**app_info)
            APP_Manager.delete_app_user(app)
            log.info(app_info)
            return JSONResponse({"result": "SUCCESS"})
        except Exception, e:
            log.error(traceback.format_exc())
            return JSONResponse(e.args[0], status=200)

































































