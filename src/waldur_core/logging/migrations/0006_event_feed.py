# -*- coding: utf-8 -*-
# Generated by Django 1.11.20 on 2019-05-14 08:24
import django.contrib.postgres.fields.jsonb
import django.db.models.deletion
import django.utils.timezone
import model_utils.fields
from django.db import migrations, models

import waldur_core.core.fields


class Migration(migrations.Migration):

    dependencies = [
        ('contenttypes', '0002_remove_content_type_name'),
        ('logging', '0005_report'),
    ]

    operations = [
        migrations.CreateModel(
            name='Event',
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
                ('uuid', waldur_core.core.fields.UUIDField()),
                (
                    'created',
                    model_utils.fields.AutoCreatedField(
                        default=django.utils.timezone.now, editable=False
                    ),
                ),
                ('event_type', models.CharField(db_index=True, max_length=100)),
                ('message', models.TextField()),
                ('context', django.contrib.postgres.fields.jsonb.JSONField(blank=True)),
            ],
            options={'abstract': False, 'ordering': ('-created',),},
        ),
        migrations.CreateModel(
            name='Feed',
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
                ('object_id', models.PositiveIntegerField(db_index=True)),
                (
                    'content_type',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to='contenttypes.ContentType',
                    ),
                ),
                (
                    'event',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to='logging.Event'
                    ),
                ),
            ],
        ),
    ]
