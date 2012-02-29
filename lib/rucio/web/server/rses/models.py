from django.db import models

# Create your models here.

class Tag(models.Model):
    """ RSE Tag """
    tag_name        = models.CharField(max_length=100)
    tag_description = models.CharField(max_length=300)
    reg_date        = models.DateTimeField('date published')

class RSE(models.Model):
    """ Rucio Storage Element (RSE) - Basic Storage Unit in Rucio """
    rse_name  = models.CharField(max_length=200)
    site_name = models.CharField(max_length=200)
    end_point = models.CharField(max_length=200)
    tag       = models.ManyToManyField(Tag)
    reg_date  = models.DateTimeField('date published')

