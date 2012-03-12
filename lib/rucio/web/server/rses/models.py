# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012

from django.db import models

# Create your models here.


class Tag(models.Model):
    """ RSE Tag """
    tag_name = models.CharField(max_length=100)
    tag_description = models.CharField(max_length=300)
    reg_date = models.DateTimeField('date published')


class RSE(models.Model):
    """ Rucio Storage Element (RSE) - Basic Storage Unit in Rucio """
    rse_name = models.CharField(max_length=200)
    site_name = models.CharField(max_length=200)
    end_point = models.CharField(max_length=200)
    tag = models.ManyToManyField(Tag)
    reg_date = models.DateTimeField('date published')
