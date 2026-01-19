# -*- coding: utf-8 -*-
# 项目基本配置，线上线下通用
import os
import logging
import platform
import socket

SYSTEM_TYPE = platform.architecture()
if "windows" in str(SYSTEM_TYPE).lower():
#日志
    LOGGING_PATH = "D:\\pdns"
else:
    LOGGING_PATH = "/home/work/pdns-server/logs"
if not os.path.exists(LOGGING_PATH):
    os.makedirs(LOGGING_PATH)

DEBUG = True
TEMPLATE_DEBUG = DEBUG
TIME_ZONE = 'Asia/Shanghai'
PROJECT_PATH = os.path.dirname(__file__)
HERE = os.path.dirname(os.path.abspath(__file__))
HERE = os.path.join(HERE, '/')
GIT_REF = '@@GIT_REF@@'
GIT_SHA1 = '@@GIT_SHA1@@'
TITLE_INFO_BAR = 'PDNS-MGR-test'
LOCAL_IP = socket.gethostbyname(socket.gethostname())

ADMINS = (
    ('weiguo.cwg', 'weiguo.cwg@alibaba-inc.com'),
)
MANAGERS = ADMINS

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'PDNS_APP',
        'USER': 'PDNS_APP',
        'PASSWORD': 'nkpwcsos',
        'HOST': '42.156.239.143',
        'PORT': '9999'
    },
}

# hase db url
OTS_HOST =  "data-dapan.alibaba-inc.com"

DB_CONFIG = DATABASES.get("default")
LANGUAGE_CODE = 'zh-cn'
SITE_ID = 1
USE_I18N = True
USE_L10N = True
MEDIA_URL = ''
STATIC_ROOT = os.path.join(PROJECT_PATH, "static/")
STATIC_URL = '/static/'
STATICFILES_DIRS = (
)
STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
    'compressor.finders.CompressorFinder',
)
SECRET_KEY = '(!7wtjt7y^tehz^aoytx1bd&amp;xniiv$1(513r%@&amp;19_)_8szzj@'
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.Loader',
    'django.template.loaders.app_directories.Loader',
)

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
)
ROOT_URLCONF = 'pdns.urls'
WSGI_APPLICATION = 'pdns.wsgi.application'
TEMPLATE_DIRS = (
    os.path.join(PROJECT_PATH, 'templates/'),
)
INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.admin',
    'django.contrib.admindocs',
    'pdns_app',
    "django_cron"
)
COMPRESS_PRECOMPILERS = (
    ('text/coffeescript', 'coffee --compile --stdio'),
    ('text/less', 'lessc {infile} {outfile}'),
    ('text/x-sass', 'sass {infile} {outfile}'),
    ('text/x-scss', 'sass --scss {infile} {outfile}'),
)
LOGIN_URL = 'https://login-test.alibaba-inc.com/ssoLogin.htm?APP_NAME=hichina-adms&BACK_URL=http://127.0.0.1:8000'
ALI_SSO_SERVER = 'login-test.alibaba-inc.com'
AUTHENTICATION_BACKENDS = (
    'pdns_app.backends.AliSSOUserBackend',
    'django.contrib.auth.backends.ModelBackend',
)

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.db.DatabaseCache',
        'LOCATION': 'mycron_cache_table',
    }
}
CRON_CLASSES = []

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'filters': {
    },
    'formatters': {
        'standard': {
            'format': '%(asctime)s - %(levelname)s-{%(filename)s:%(lineno)d}: %(message)s'
        },
        'api': {
            'format': '%(asctime)s - %(levelname)s-{%(filename)s:%(funcName)s:%(lineno)d}: %(message)s'
        }
    },
    'handlers': {
        'db': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': os.path.join(LOGGING_PATH, 'pdns-db.log'),
            'formatter': "standard",
        },
        'default': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': os.path.join(LOGGING_PATH, 'pdns-web.log'),
            'formatter': "standard",
        },
        'crontab': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': os.path.join(LOGGING_PATH, 'pdns-cron.log'),
            'formatter': "standard",
        },
        'console':{
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': "standard",
        }
    },
    'loggers': {
        'django': {
            'handlers': ['default', 'console'],
            # 'handlers': ['default'],
            'level': 'DEBUG',
            'propagate': True,
        },
        'django.db.backends': {
            'handlers': ['db', 'console'],
            # 'handlers': ['db'],
            'level': 'DEBUG',
            'propagate': True,
        },
        'pdns_app': {
            'handlers': ['default', 'console'],
            # 'handlers': ['default'],
            'level': 'INFO',
            'propagate': True,
        },
        'cron': {
            'handlers': ['crontab', 'console'],
            # 'handlers': ['crontab'],
            'level': 'INFO',
            'propagate': True,
        }
    }
}
