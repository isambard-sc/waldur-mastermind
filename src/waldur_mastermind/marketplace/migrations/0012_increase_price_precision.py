# Generated by Django 2.2.9 on 2020-02-24 13:15

from decimal import Decimal

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('marketplace', '0011_offering_datacite_doi'),
    ]

    operations = [
        migrations.AlterField(
            model_name='plancomponent',
            name='price',
            field=models.DecimalField(
                decimal_places=10,
                default=0,
                max_digits=22,
                validators=[django.core.validators.MinValueValidator(Decimal('0'))],
                verbose_name='Price per unit per billing period.',
            ),
        ),
    ]