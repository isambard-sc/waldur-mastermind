# Generated by Django 3.2.16 on 2022-12-07 11:06

from django.db import migrations, models

MARKER = 999999999


class Migration(migrations.Migration):

    dependencies = [
        ('structure', '0036_remove_notification_and_notification_template'),
    ]

    def add_placeholder_values(apps, schema_editor):
        Customer = apps.get_model('structure', 'Customer')
        Customer.objects.filter(agreement_number__isnull=True).update(
            agreement_number=MARKER
        )

    operations = [
        migrations.RunPython(add_placeholder_values),
        migrations.AlterField(
            model_name='customer',
            name='agreement_number',
            field=models.CharField(blank=True, default='', max_length=160),
        ),
    ]