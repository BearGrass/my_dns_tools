from django.conf.urls import patterns, include, url
from pdns_app.app_views import *

# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()

urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'pdns.views.home', name='home'),
    # url(r'^pdns/', include('pdns.foo.urls')),

    # Uncomment the admin/doc view below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next view to enable the admin:
    # url(r'^admin/', include(admin.site.urls)),
    url(r'^', include('pdns_app.app_urls')),
    (r'^sendBucSSOToken*', login),
)
