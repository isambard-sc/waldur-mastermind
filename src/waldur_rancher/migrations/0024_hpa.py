# Generated by Django 2.2.10 on 2020-06-16 14:21

import django.contrib.postgres.fields.jsonb
import django.db.models.deletion
import django.utils.timezone
import model_utils.fields
from django.db import migrations, models

import waldur_core.core.fields
import waldur_core.core.validators


class Migration(migrations.Migration):

    dependencies = [
        ('structure', '0012_customer_sponsor_number'),
        ('waldur_rancher', '0023_workload'),
    ]

    operations = [
        migrations.CreateModel(
            name='HPA',
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
                    'name',
                    models.CharField(
                        max_length=150,
                        validators=[waldur_core.core.validators.validate_name],
                        verbose_name='name',
                    ),
                ),
                ('uuid', waldur_core.core.fields.UUIDField()),
                (
                    'runtime_state',
                    models.CharField(
                        blank=True, max_length=150, verbose_name='runtime state'
                    ),
                ),
                ('backend_id', models.CharField(blank=True, max_length=255)),
                ('current_replicas', models.PositiveSmallIntegerField(default=0)),
                ('desired_replicas', models.PositiveSmallIntegerField(default=0)),
                ('min_replicas', models.PositiveSmallIntegerField(default=0)),
                ('max_replicas', models.PositiveSmallIntegerField(default=0)),
                ('metrics', django.contrib.postgres.fields.jsonb.JSONField()),
                (
                    'cluster',
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='+',
                        to='waldur_rancher.Cluster',
                    ),
                ),
                (
                    'namespace',
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='+',
                        to='waldur_rancher.Namespace',
                    ),
                ),
                (
                    'project',
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='+',
                        to='waldur_rancher.Project',
                    ),
                ),
                (
                    'settings',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='+',
                        to='structure.ServiceSettings',
                    ),
                ),
                (
                    'workload',
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='+',
                        to='waldur_rancher.Workload',
                    ),
                ),
            ],
            options={'ordering': ('name',),},
        ),
    ]