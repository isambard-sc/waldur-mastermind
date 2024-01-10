# Generated by Django 3.2.20 on 2023-12-18 15:30

import django.db.models.deletion
import django.utils.timezone
import django_fsm
import model_utils.fields
from django.conf import settings
from django.db import migrations, models

import waldur_core.core.fields


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("proposal", "0005_proposal_state"),
    ]

    operations = [
        migrations.AlterField(
            model_name="call",
            name="created_by",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="+",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.CreateModel(
            name="CallReviewer",
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
                ("uuid", waldur_core.core.fields.UUIDField()),
                (
                    "call",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="proposal.call"
                    ),
                ),
                (
                    "created_by",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="+",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="+",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "unique_together": {("user", "call")},
            },
        ),
        migrations.AddField(
            model_name="call",
            name="reviewers",
            field=models.ManyToManyField(
                through="proposal.CallReviewer", to=settings.AUTH_USER_MODEL
            ),
        ),
        migrations.AddField(
            model_name="review",
            name="reviewer",
            field=models.ForeignKey(
                default=1,
                on_delete=django.db.models.deletion.CASCADE,
                to="proposal.callreviewer",
            ),
            preserve_default=False,
        ),
        migrations.RemoveField(
            model_name="review",
            name="points",
        ),
        migrations.RemoveField(
            model_name="review",
            name="type",
        ),
        migrations.RemoveField(
            model_name="review",
            name="version",
        ),
        migrations.AddField(
            model_name="review",
            name="summary_private_comment",
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name="review",
            name="summary_public_comment",
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name="review",
            name="summary_score",
            field=models.PositiveSmallIntegerField(blank=True, default=0),
        ),
        migrations.AlterField(
            model_name="review",
            name="state",
            field=django_fsm.FSMIntegerField(
                choices=[
                    (1, "Created"),
                    (2, "In review"),
                    (3, "Submitted"),
                    (4, "Rejected"),
                ],
                default=1,
            ),
        ),
    ]
