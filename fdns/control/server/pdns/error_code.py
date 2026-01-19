#coding=utf-8
OK = {"result": "000000", "message": "OK"}

#参数校验错误
PARAMETER_ERROR = {"result": "6000001", "message": ""}

#Database
DB_ACTION_FAILED={"result":"140001","message":"db action failed"}
DB_SUCCESS_STATUS={"result":"999999", "message":"task action success"}

#Unknown
UNKNOWN_FAILED={"result":"990000","message":"unknown failed"}

#VIEW
VIEW_NOT_EXIST = {"result": "500001", "message": "view not exist"}

#PDNS SERVER
FORWARDER_NOT_EXIST = {"result": "300001", "message": "forwarder not exist"}
PDNS_SERVER_NOT_EXIST = {"result": "300002", "message": "pdns server not exist"}

#DOMAIN
DOMAIN_NAME_ERROR = {"result": "700006", "message": "domain name error"}

#APP_USER
APP_USER_EXIST = {"result": "120001", "message": "app user exist"}
APP_USER_NOT_EXIST = {"result": "120002", "message": "app user is not exist"}

#PERMISION
PERMISSION_DENIED = {"result": "110001", "message": "permission denied"}
SUPERUSER_ONLY = {"result": "110003", "message": "super user only"}