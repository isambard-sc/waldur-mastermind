# Generated by Django 4.2.8 on 2024-01-08 13:44

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("proposal", "0007_drop_start_end_time_from_call"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="call",
            name="round_strategy",
        ),
    ]