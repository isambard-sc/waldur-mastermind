# Generated by Django 3.2.20 on 2023-11-20 22:59

import django.db.models.deletion
import django.utils.timezone
import model_utils.fields
from django.db import migrations, models

import waldur_core.core.fields
import waldur_core.media.models


class Migration(migrations.Migration):
    dependencies = [
        ('structure', '0040_useragreement_uuid'),
        ('proposal', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='CallManager',
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
                (
                    'created',
                    model_utils.fields.AutoCreatedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name='created',
                    ),
                ),
                (
                    'modified',
                    model_utils.fields.AutoLastModifiedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name='modified',
                    ),
                ),
                (
                    'image',
                    models.ImageField(
                        blank=True,
                        null=True,
                        upload_to=waldur_core.media.models.get_upload_path,
                    ),
                ),
                (
                    'description',
                    models.CharField(
                        blank=True, max_length=2000, verbose_name='description'
                    ),
                ),
                ('uuid', waldur_core.core.fields.UUIDField()),
                (
                    'customer',
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        to='structure.customer',
                    ),
                ),
            ],
            options={
                'verbose_name': 'Call manager',
            },
        ),
    ]
