# Generated by Django 3.2.20 on 2023-10-10 12:50
import uuid

from django.db import migrations, models

import waldur_core.core.fields


def gen_uuid(apps, schema_editor):
    UserAgreement = apps.get_model('structure', 'UserAgreement')
    for row in UserAgreement.objects.all():
        row.uuid = uuid.uuid4().hex
        row.save(update_fields=['uuid'])


class Migration(migrations.Migration):
    dependencies = [
        ('structure', '0039_project_end_date_requested_by'),
    ]

    operations = [
        migrations.AddField(
            model_name='useragreement',
            name='uuid',
            field=models.UUIDField(null=True),
        ),
        migrations.RunPython(gen_uuid, elidable=True),
        migrations.AlterField(
            model_name='useragreement',
            name='uuid',
            field=waldur_core.core.fields.UUIDField(),
        ),
    ]