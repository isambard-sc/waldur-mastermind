# Generated by Django 2.2.13 on 2020-11-23 13:44

from django.db import migrations, models


def fill_new_geo_fields(apps, schema_editor):
    Offering = apps.get_model('marketplace', 'Offering')
    for offering in Offering.objects.all():
        if offering.geolocations:
            geolocation = offering.geolocations[0]
            offering.latitude = geolocation['latitude']
            offering.longitude = geolocation['longitude']
            offering.save()


class Migration(migrations.Migration):
    dependencies = [
        ('marketplace', '0033_mandatory_offering_type'),
    ]

    operations = [
        migrations.AddField(
            model_name='offering',
            name='latitude',
            field=models.FloatField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='offering',
            name='longitude',
            field=models.FloatField(blank=True, null=True),
        ),
        migrations.RunPython(fill_new_geo_fields),
        migrations.RemoveField(model_name='offering', name='geolocations',),
    ]