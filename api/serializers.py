"""serializers.py
DetailsSerializer maps IPDetails to JSON output.  You'll find many
references to other serializers beyond serializers.Field() in the
DRF framework.  Ignore that for now since we are reading data back
only and not writing.  You will need to use
serializers.Field(many=true) for activity output, however.
"""

import datetime
import calendar

from rest_framework import serializers

from threat import IPDetails
from models import *


class DetailsSerializer(serializers.Serializer):
    # TODO: serialize the rest of your values in IPDetails here
    # use of the simple serializers.Field() is acceptable
    address = serializers.ReadOnlyField()
    id = serializers.ReadOnlyField()
    reputation_val =serializers.ReadOnlyField()
    first_activity = serializers.ReadOnlyField()
    last_activity = serializers.ReadOnlyField()
    activities = serializers.ReadOnlyField()
    activity_types = serializers.ReadOnlyField()
    is_valid = serializers.ReadOnlyField()


class VisitListingField(serializers.PrimaryKeyRelatedField):
    def to_representation(self, value):
        timestamp_epoch_sec = calendar.timegm(value.timestamp.timetuple())
        return "{'address': {!s}, 'timestamp': {!d}, 'endpoint': {!s}},".format(value.address, timestamp_epoch_sec, value.endpoint)


class VisitSerializer(serializers.ModelSerializer):
    class Meta:
        model = Visit
        fields = ('address', 'timestamp', 'endpoint')


class VisitorSerializer(serializers.ModelSerializer):
    # visits = VisitSerializer(many=True)
    visits = VisitSerializer(many=True, read_only=True)

    class Meta:
        model = Visitor
        fields = ('alienvaultid', 'visits')
        extra_kwargs = {
            "alienvaultid": {
                "read_only": False,
                "required": False,
            },
        }
