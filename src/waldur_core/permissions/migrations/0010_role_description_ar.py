# Generated by Django 3.2.20 on 2023-10-30 08:47

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('permissions', '0009_drop_duplicates'),
    ]

    operations = [
        migrations.AddField(
            model_name='role',
            name='description_ar',
            field=models.CharField(
                blank=True, max_length=2000, null=True, verbose_name='description'
            ),
        ),
    ]
