# Generated by Django 3.2.20 on 2023-12-11 20:57

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("structure", "0040_useragreement_uuid"),
    ]

    operations = [
        migrations.DeleteModel(
            name="CustomerPermission",
        ),
        migrations.DeleteModel(
            name="ProjectPermission",
        ),
    ]
