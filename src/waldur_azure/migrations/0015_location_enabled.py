# -*- coding: utf-8 -*-
# Generated by Django 1.11.18 on 2019-02-27 13:38
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('waldur_azure', '0014_networkinterface_ip_address'),
    ]

    operations = [
        migrations.AddField(
            model_name='location',
            name='enabled',
            field=models.BooleanField(
                default=True,
                help_text='Indicates whether location is available for resource group.',
            ),
        ),
    ]
