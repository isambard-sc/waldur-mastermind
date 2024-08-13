# Generated by Django 4.2.14 on 2024-08-09 10:59

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0010_generate_missing_fingerprint"),
    ]

    operations = [
        migrations.AddField(
            model_name="user",
            name="identity_source",
            field=models.CharField(
                blank=True,
                default="",
                help_text="Indicates what identity provider was used.",
                max_length=50,
                verbose_name="source of identity",
            ),
        ),
        migrations.AlterField(
            model_name="user",
            name="registration_method",
            field=models.CharField(
                blank=True,
                default="default",
                help_text="Indicates what registration method was used.",
                max_length=50,
                verbose_name="registration method",
            ),
        ),
    ]
