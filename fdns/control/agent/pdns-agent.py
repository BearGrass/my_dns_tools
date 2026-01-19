#coding=utf-8
__author__ = 'weiguo.cwg'
import logging
import traceback
import json
import commands

from flask import Flask, request
from flask.ext import restful
from flask.ext.restful import Resource, reqparse, marshal, fields

from conf import settings,constants
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                    datefmt='%a, %d %b %Y %H:%M:%S',
                    filename="%s/%s.log" % (settings.LOGGING_PATH, settings.LOG_HANDLE_NAME),
                    filemode='a')
log = logging.getLogger(settings.LOG_HANDLE_NAME)


from util import WSGICopyBody
from pdns_manager import pdns_manager

app = Flask(__name__)
app.wsgi_app = WSGICopyBody.WSGICopyBody(app.wsgi_app)
api = restful.Api(app)




class DOMAIN_DEL(Resource):
    """
        "server_type":""
        "domain_list" : [{
            "id":int(task[0]),
            "zone":zone,
            "domain_name":domain_name,
            "api":"delRr"}, {***}, {***}]
    """


    def post(self):
        log.info("api enter DOMAIN_DEL")
        RESPONSE_OK = {
            "code": "000",
            "success": True,
            "message": "ok"
        }
        try:
            params = self.request_args()
            type = params.get("server_type")
            domain_list = params.get("domain_list")
            log.info("server type:%s, domain list:%s" % (type, domain_list))
            res = pdns_manager.del_domain(type, domain_list)
            if 0 != len(res["error"]):
                RESPONSE_OK["success"] = False
                RESPONSE_OK["msg"] = res
            return RESPONSE_OK

        except Exception, e:
            log.error("DOMAIN_DEL error:%s" % traceback.format_exc())
            RESPONSE_OK["success"] = False
            RESPONSE_OK["msg"] = e.args[0]
            return RESPONSE_OK

    def request_args(self):
        request.values = json.loads(request.environ['body_copy'])
        parser = reqparse.RequestParser()
        parser.add_argument('server_type', type=str, help='agent类型', required=True)
        parser.add_argument('domain_list', type=list, help='删除rr列表', required=True)
        return parser.parse_args()

class SERRVER_MONITOR(Resource):
    def post(self):
        log.info("enter api:SERRVER_MONITOR")
        try:
            ret_value = {
                "pdns_process":"offline",
                "pdns_version":"",
                "agent_version": "",
                "agent_status": "online",
                "success": True
            }
            params = self.request_args()
            log.info("params:%s" % str(params))
            server_type = params.get("server_type")
            ret_value["server_type"] = server_type

            check_process_cmd_format = """ps -ef | grep '%(process)s' | grep -v grep | awk '{ print $2 }'"""
            cmd_preocess_output = "online"
            cmd_version_output = ""
            if constants.SERVER_TYPE_FWD == server_type:
                status, cmd_preocess_output = commands.getstatusoutput(check_process_cmd_format % {'process': 'fwd_dns_dpdk'})
                status, cmd_version_output = commands.getstatusoutput("rpm -qa|grep fdns")
            elif constants.SERVER_TYPE_CDN == server_type:
                status, cmd_preocess_output = commands.getstatusoutput(check_process_cmd_format % {'process': 'named'})
                status, cmd_version_output = commands.getstatusoutput("rpm -qa|grep pdns-bind")
            elif constants.SERVER_TYPE_REDIS == server_type:
                pass

            ret_value["pdns_process"] = 'online' if cmd_preocess_output.strip() != '' else 'offline'
            ret_value["pdns_version"] = cmd_version_output.strip()
            ret_value["agent_version"] = "%s(%s)" % (settings.GIT_REF, settings.GIT_SHA1)

            log.info("pdns server status check result:%s" % str(ret_value))
            return ret_value
        except:
            log.error("api monitor_server error:%s" % traceback.format_exc())
            log.error("pdns server status check result:%s" % str(ret_value))
            return ret_value


    def request_args(self):
        request.values = json.loads(request.environ['body_copy'])
        parser = reqparse.RequestParser()
        parser.add_argument('server_type', type=str, help='agent类型', required=True)
        return parser.parse_args()


api.add_resource(DOMAIN_DEL, "/del_domain")
api.add_resource(SERRVER_MONITOR, "/monitor_server")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9999, debug=True)
