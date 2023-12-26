# Generated by Django 4.2.8 on 2023-12-20 12:37

from django.db import migrations


def drop_role_permission_duplicates(apps, schema_editor):
    RolePermission = apps.get_model('permissions', 'RolePermission')
    role_permissions = RolePermission.objects.values_list('id', 'role', 'permission')
    distinct_role_permissions = set()
    for role_permission in role_permissions:
        mapping = role_permission[1:]
        if mapping in distinct_role_permissions:
            id_ = role_permission[0]
            RolePermission.objects.get(id=id_).delete()
        else:
            distinct_role_permissions.add(mapping)


class Migration(migrations.Migration):
    dependencies = [
        ('permissions', '00012_rename_order_item_permissions'),
    ]

    operations = [
        migrations.RunPython(drop_role_permission_duplicates),
        migrations.AlterUniqueTogether(
            name='rolepermission',
            unique_together={('role', 'permission')},
        ),
    ]