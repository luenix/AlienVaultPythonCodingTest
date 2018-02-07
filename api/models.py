from django.utils import timezone

from django.db import models


class Visitor(models.Model):
    # alienvaultid = models.CharField(max_length=12, primary_key=True)
    alienvaultid = models.CharField(max_length=12, null=False)

    class Meta:
        ordering = ['alienvaultid']


class Visit(models.Model):
    visitor = models.ForeignKey(Visitor, related_name='visits', on_delete=models.CASCADE)
    address = models.CharField(max_length=39, null=True)
    timestamp = models.DateTimeField(default=timezone.now)
    endpoint = models.CharField(max_length=255, null=True)

    class Meta:
        ordering = ['timestamp']

