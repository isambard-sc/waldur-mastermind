# Generated by Django 3.2.18 on 2023-03-01 17:22

from django.db import migrations


def update_username_to_lowercase(apps, schema_editor):
    Profile = apps.get_model('waldur_freeipa', 'Profile')
    for freeipa_profile in Profile.objects.all():
        freeipa_profile.username = freeipa_profile.username.lower()
        freeipa_profile.save()


class Migration(migrations.Migration):
    dependencies = [
        ('waldur_freeipa', '0003_is_active_false'),
    ]

    operations = [
        migrations.RunPython(update_username_to_lowercase),
    ]
