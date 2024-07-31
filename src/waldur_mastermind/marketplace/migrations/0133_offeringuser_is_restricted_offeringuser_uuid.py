# Generated by Django 4.2.10 on 2024-07-26 06:50
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("marketplace", "0132_offering_slug_resource_slug"),
    ]

    operations = [
        migrations.AddField(
            model_name="offeringuser",
            name="is_restricted",
            field=models.BooleanField(
                default=False,
                help_text="Signal to service if the user account is restricted or not",
            ),
        ),
    ]