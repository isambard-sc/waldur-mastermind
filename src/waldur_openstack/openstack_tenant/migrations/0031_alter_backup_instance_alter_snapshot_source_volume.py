# Generated by Django 4.2.10 on 2024-02-23 17:03

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("openstack_tenant", "0030_allow_directly_connected_external_networks"),
    ]

    operations = [
        migrations.AlterField(
            model_name="backup",
            name="instance",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="backups",
                to="openstack_tenant.instance",
            ),
        ),
        migrations.AlterField(
            model_name="snapshot",
            name="source_volume",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="snapshots",
                to="openstack_tenant.volume",
            ),
        ),
    ]