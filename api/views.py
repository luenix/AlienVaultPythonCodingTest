"""views.py
urls.py calls a view from views.py.  In this case, the views are
subclassed from DRF APIView.  For this exercise, the view is a simple
call to generate an IPDetails object, located in threat.py
"""

import random

from django.http import HttpResponseRedirect
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.reverse import reverse
from rest_framework import status

from threat import *
from serializers import *
from views import *
from models import *

class APIRoot(APIView):
    def get(self, request, redirect_to=None, *args, **kwargs):
        if redirect_to:
            response = HttpResponseRedirect(reverse(redirect_to, request=request))
        else:
            response = Response({
            'IP Details': [
                {
                    'IP Details (Empty)': reverse('api:threat_details', request=request),
                    'IP Details (Known Bad)': reverse('api:threat_details', request=request) + "69.43.161.174",
                    'IP Details (Known Good)': reverse('api:threat_details', request=request) + "8.8.8.8",
                    'IP Details (Malformed)': reverse('api:threat_details', request=request) + "1.2.3.4.5",
                    'IP Details (Invalid)': reverse('api:threat_details', request=request) + "255.255.255.256"
                }
            ],
            'Traffic': reverse('api:traffic', request=request)
        })
        return response


class IPDetailsView(APIView):
    # TODO: get ip from the url e.g. /api/threat/ip/1.2.3.4
    def get(self, request, ip=None, *args, **kwargs):
        response = Response()
        alienvaultid = None

        if 'alienvaultid' in request.COOKIES:
            print "Found cookie.\nalienvaultid: {!s}".format(request.COOKIES['alienvaultid'])
            alienvaultid = request.COOKIES['alienvaultid']
        else:
            alienvaultid = ''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for i in range(12))
            response.set_cookie('alienvaultid', alienvaultid, max_age=365*24*60*60)
            print "Set cookie.\nalienvaultid: {!s}".format(alienvaultid)

        current_visitor = Visitor(alienvaultid=alienvaultid)
        current_visitor.save()
        current_visitor_serializer = VisitorSerializer(current_visitor)

        current_visit = Visit(
                      visitor=current_visitor,
                      address=request.META.get('REMOTE_ADDR'),
                      endpoint=request.path
                     )
        current_visit.is_valid()
        current_visit.save()
        current_visit_serializer = VisitSerializer(current_visit)

        print "current_visitor_serializer.data:"
        print current_visitor_serializer.data

        print "current_visit_serializer.data:"
        print current_visit_serializer.data

        try:
            details_request = IPDetails(ip, *args, **kwargs)

            if details_request is None:
                raise CustomAPIViewError("details_request is None")

            result = DetailsSerializer(details_request)

            if result.data is None:
                raise CustomAPIViewError("result is None")

            response.data = result.data
            response.status = status.HTTP_200_OK
        except CustomAPIViewError as e:
            response.data = "Something went wrong: {!s}".format(e)
            response.status = status.HTTP_400_BAD_REQUEST
        except:
            response.data = "No information could be found for IP: {!s}".format(ip)
            response.status = status.HTTP_400_BAD_REQUEST
        finally:
            return response


# TODO: View for /api/traffic
class TrafficView(APIView):
    def get(self, request, *args, **kwargs):
        response = Response()

        all_visitors = Visitor.objects.all()
        all_visitors_serializer = VisitorSerializer(all_visitors)

        print "all_visitors:"
        print type(all_visitors), all_visitors
        print "all_visitors_serializer:"
        print type(all_visitors_serializer), all_visitors_serializer
        print "all_visitors_serializer.data:"
        print type(all_visitors_serializer.data), all_visitors_serializer.data

        response.data = all_visitors_serializer.data
        response.status = status.HTTP_200_OK

        return response


class APIViewError(Exception):
    """Base class for exceptions in this module"""
    pass


class CustomAPIViewError(APIViewError):
    """Exception raised for errors with lazy messaging baked in.

    Attributes:
        msg  -- explanation of the error
    """

    def __init__(self, msg):
        self.msg = msg

    def __unicode__(self):
        return self.msg