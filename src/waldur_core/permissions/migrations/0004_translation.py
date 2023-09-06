# Generated by Django 3.2.20 on 2023-09-01 06:45

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('permissions', '0003_role_is_system_role'),
    ]

    operations = [
        migrations.AddField(
            model_name='role',
            name='description_da',
            field=models.CharField(
                blank=True, max_length=2000, null=True, verbose_name='description'
            ),
        ),
        migrations.AddField(
            model_name='role',
            name='description_de',
            field=models.CharField(
                blank=True, max_length=2000, null=True, verbose_name='description'
            ),
        ),
        migrations.AddField(
            model_name='role',
            name='description_en',
            field=models.CharField(
                blank=True, max_length=2000, null=True, verbose_name='description'
            ),
        ),
        migrations.AddField(
            model_name='role',
            name='description_es',
            field=models.CharField(
                blank=True, max_length=2000, null=True, verbose_name='description'
            ),
        ),
        migrations.AddField(
            model_name='role',
            name='description_et',
            field=models.CharField(
                blank=True, max_length=2000, null=True, verbose_name='description'
            ),
        ),
        migrations.AddField(
            model_name='role',
            name='description_fr',
            field=models.CharField(
                blank=True, max_length=2000, null=True, verbose_name='description'
            ),
        ),
        migrations.AddField(
            model_name='role',
            name='description_it',
            field=models.CharField(
                blank=True, max_length=2000, null=True, verbose_name='description'
            ),
        ),
        migrations.AddField(
            model_name='role',
            name='description_lt',
            field=models.CharField(
                blank=True, max_length=2000, null=True, verbose_name='description'
            ),
        ),
        migrations.AddField(
            model_name='role',
            name='description_lv',
            field=models.CharField(
                blank=True, max_length=2000, null=True, verbose_name='description'
            ),
        ),
        migrations.AddField(
            model_name='role',
            name='description_nb',
            field=models.CharField(
                blank=True, max_length=2000, null=True, verbose_name='description'
            ),
        ),
        migrations.AddField(
            model_name='role',
            name='description_ru',
            field=models.CharField(
                blank=True, max_length=2000, null=True, verbose_name='description'
            ),
        ),
        migrations.AddField(
            model_name='role',
            name='description_sv',
            field=models.CharField(
                blank=True, max_length=2000, null=True, verbose_name='description'
            ),
        ),
    ]