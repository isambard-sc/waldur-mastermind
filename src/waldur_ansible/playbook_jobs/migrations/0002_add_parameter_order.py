# -*- coding: utf-8 -*-
# Generated by Django 1.11.1 on 2017-07-28 15:27
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('playbook_jobs', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='playbookparameter', options={'ordering': ['order']},
        ),
        migrations.AddField(
            model_name='playbookparameter',
            name='order',
            field=models.PositiveIntegerField(default=0),
        ),
    ]
