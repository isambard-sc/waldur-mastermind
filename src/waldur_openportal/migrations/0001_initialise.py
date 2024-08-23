# Generated by Django 3.2.16 on 2023-01-05 00:17

import re

import django.core.validators
import django.db.models.deletion
import django.utils.timezone
import django_fsm
import model_utils.fields
from django.conf import settings
from django.db import migrations, models

import waldur_core.core.fields
import waldur_core.core.models
import waldur_core.core.validators
import waldur_core.logging.loggers


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("structure", "0001_squashed_0036"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Allocation",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "created",
                    model_utils.fields.AutoCreatedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name="created",
                    ),
                ),
                (
                    "modified",
                    model_utils.fields.AutoLastModifiedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name="modified",
                    ),
                ),
                (
                    "description",
                    models.CharField(
                        blank=True, max_length=2000, verbose_name="description"
                    ),
                ),
                (
                    "name",
                    models.CharField(
                        max_length=150,
                        validators=[waldur_core.core.validators.validate_name],
                        verbose_name="name",
                    ),
                ),
                ("uuid", waldur_core.core.fields.UUIDField()),
                ("error_message", models.TextField(blank=True)),
                (
                    "state",
                    django_fsm.FSMIntegerField(
                        choices=[
                            (5, "Creation Scheduled"),
                            (6, "Creating"),
                            (1, "Update Scheduled"),
                            (2, "Updating"),
                            (7, "Deletion Scheduled"),
                            (8, "Deleting"),
                            (3, "OK"),
                            (4, "Erred"),
                        ],
                        default=5,
                    ),
                ),
                ("backend_id", models.CharField(blank=True, max_length=255)),
                ("cpu_limit", models.BigIntegerField(default=0)),
                ("cpu_usage", models.BigIntegerField(default=0)),
                ("is_active", models.BooleanField(default=True)),
                ("gpu_limit", models.BigIntegerField(default=0)),
                ("gpu_usage", models.BigIntegerField(default=0)),
                ("ram_limit", models.BigIntegerField(default=0)),
                ("ram_usage", models.BigIntegerField(default=0)),
                ("error_traceback", models.TextField(blank=True)),
                (
                    "project",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="+",
                        to="structure.project",
                    ),
                ),
                (
                    "service_settings",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="+",
                        to="structure.servicesettings",
                    ),
                ),
            ],
            options={
                "abstract": False,
            },
            bases=(
                waldur_core.core.models.DescendantMixin,
                waldur_core.core.models.BackendModelMixin,
                waldur_core.logging.loggers.LoggableMixin,
                models.Model,
            ),
        ),
        migrations.CreateModel(
            name="Association",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("uuid", waldur_core.core.fields.UUIDField()),
                (
                    "username",
                    models.CharField(
                        max_length=128,
                        validators=[
                            django.core.validators.RegexValidator(
                                re.compile(
                                    "^[a-zA-Z0-9_.][a-zA-Z0-9_.-]*[a-zA-Z0-9_.$-]?$"
                                ),
                                "Enter a valid username.",
                                "invalid",
                            )
                        ],
                    ),
                ),
                (
                    "allocation",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="associations",
                        to="waldur_openportal.allocation",
                    ),
                ),
            ],
            options={
                "abstract": False,
            },
        ),
        migrations.CreateModel(
            name="AllocationUserUsage",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("username", models.CharField(max_length=32)),
                ("cpu_usage", models.BigIntegerField(default=0)),
                ("ram_usage", models.BigIntegerField(default=0)),
                ("gpu_usage", models.BigIntegerField(default=0)),
                (
                    "user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "allocation",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="waldur_openportal.allocation",
                    ),
                ),
                (
                    "month",
                    models.PositiveSmallIntegerField(
                        validators=[
                            django.core.validators.MinValueValidator(1),
                            django.core.validators.MaxValueValidator(12),
                        ]
                    ),
                ),
                ("year", models.PositiveSmallIntegerField()),
            ],
        ),
    ]
