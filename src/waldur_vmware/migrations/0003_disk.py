# Generated by Django 1.11.21 on 2019-06-25 13:05
import django.db.models.deletion
import django.utils.timezone
import django_fsm
import model_utils.fields
from django.db import migrations, models

import waldur_core.core.fields
import waldur_core.core.models
import waldur_core.core.shims
import waldur_core.core.validators
import waldur_core.structure.models


class Migration(migrations.Migration):

    dependencies = [
        ('waldur_vmware', '0002_virtualmachine'),
    ]

    operations = [
        migrations.CreateModel(
            name='Disk',
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
                    'description',
                    models.CharField(
                        blank=True, max_length=500, verbose_name='description'
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
                ('error_message', models.TextField(blank=True)),
                (
                    'state',
                    django_fsm.FSMIntegerField(
                        choices=[
                            (5, 'Creation Scheduled'),
                            (6, 'Creating'),
                            (1, 'Update Scheduled'),
                            (2, 'Updating'),
                            (7, 'Deletion Scheduled'),
                            (8, 'Deleting'),
                            (3, 'OK'),
                            (4, 'Erred'),
                        ],
                        default=5,
                    ),
                ),
                ('backend_id', models.CharField(blank=True, max_length=255)),
                ('size', models.PositiveIntegerField(help_text='Size in MiB')),
                (
                    'vm',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='disks',
                        to='waldur_vmware.VirtualMachine',
                    ),
                ),
            ],
            options={'abstract': False, 'ordering': ['-created']},
            bases=(
                waldur_core.core.models.DescendantMixin,
                waldur_core.core.models.BackendModelMixin,
                waldur_core.structure.models.StructureLoggableMixin,
                models.Model,
            ),
        ),
    ]
