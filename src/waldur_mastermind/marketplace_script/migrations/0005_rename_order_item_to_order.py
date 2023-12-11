# Generated by Django 3.2.20 on 2023-11-15 10:58

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ('marketplace', '0108_rename_orderitem_order'),
        ('marketplace_script', '0004_remove_dryrun_order'),
    ]

    operations = [
        migrations.RenameField(
            model_name='dryrun',
            old_name='order_item',
            new_name='order',
        ),
        migrations.RenameField(
            model_name='dryrun',
            old_name='order_item_attributes',
            new_name='order_attributes',
        ),
        migrations.RenameField(
            model_name='dryrun',
            old_name='order_item_offering',
            new_name='order_offering',
        ),
        migrations.RenameField(
            model_name='dryrun',
            old_name='order_item_plan',
            new_name='order_plan',
        ),
        migrations.RenameField(
            model_name='dryrun',
            old_name='order_item_type',
            new_name='order_type',
        ),
    ]