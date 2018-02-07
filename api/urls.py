"""urls.py
Django checks this first for routes.
Create routes for "/api/threat/ip/x.x.x.x" and "/api/traffic".
"""

from django.conf.urls import url
from rest_framework import routers

from . import views

# IPv4 regular expressions:
# basic regex: ((?:[0-9]+\.){3}[0-9]+)
# checking regex: ^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$
# grouping regex: ^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$
# validating regex: ^threat/ip/(?P<ip>(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))?$
# TODO: match /api/threat/ip/1.2.3.4
# TODO: match /api/traffic
urlpatterns = [
    url(r'^$',
        views.APIRoot.as_view(),
        name='api_root'),
    url(r'^threat/$',
        views.APIRoot.as_view(),
        {'redirect_to': 'api:threat_details'}),
    url(r'^threat/ip/(?P<ip>((?:[0-9]+\.){3}[0-9]+))?$',
        views.IPDetailsView.as_view(),
        name='threat_details'),
    url(r'^traffic/$',
        views.TrafficView.as_view(),
        name='traffic'),
]
