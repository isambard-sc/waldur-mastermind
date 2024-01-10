# Generated by Django 1.9 on 2017-05-26 13:30
import re

import django.core.validators
import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models

import waldur_core.core.fields
import waldur_freeipa.models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Profile",
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
                        help_text="Letters, numbers and ./+/-/_ characters",
                        max_length=255,
                        unique=True,
                        validators=[
                            waldur_freeipa.models.validate_username,
                            django.core.validators.RegexValidator(
                                re.compile(
                                    r"^[a-zA-Z0-9_.][a-zA-Z0-9_.-]*[a-zA-Z0-9_.$-]?$"
                                ),
                                "Enter a valid username.",
                                "invalid",
                            ),
                        ],
                        verbose_name="username",
                    ),
                ),
                (
                    "agreement_date",
                    models.DateTimeField(
                        default=django.utils.timezone.now,
                        help_text="Indicates when the user has agreed with the policy.",
                        verbose_name="agreement date",
                    ),
                ),
                ("is_active", models.BooleanField(default=True, verbose_name="active")),
                (
                    "user",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "abstract": False,
            },
        ),
    ]
