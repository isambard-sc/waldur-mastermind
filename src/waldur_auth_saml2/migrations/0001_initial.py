# -*- coding: utf-8 -*-
# Generated by Django 1.11.1 on 2017-06-10 08:44
from django.db import migrations, models

import waldur_core.core.fields


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name='IdentityProvider',
            fields=[
                (
                    'id',
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name='ID',
                    ),
                ),
                ('name', models.TextField(db_index=True)),
                ('url', models.URLField()),
                ('metadata', waldur_core.core.fields.JSONField(default={})),
            ],
            options={'ordering': ('name',),},
        ),
    ]
