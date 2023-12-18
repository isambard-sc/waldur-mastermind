# Generated by Django 3.2.16 on 2022-12-09 14:42

import django.db.models.deletion
import django.utils.timezone
import django_fsm
import model_utils.fields
from django.db import migrations, models

import waldur_core.core.fields
import waldur_mastermind.promotions.models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ('marketplace', '0001_squashed_0076'),
    ]

    operations = [
        migrations.CreateModel(
            name='Campaign',
            fields=[
                (
                    'id',
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name='ID',
                    ),
                ),
                ('uuid', waldur_core.core.fields.UUIDField()),
                (
                    'description',
                    models.CharField(
                        blank=True, max_length=2000, verbose_name='description'
                    ),
                ),
                (
                    'start_date',
                    models.DateField(
                        help_text='Starting from this date, the campaign is active.'
                    ),
                ),
                (
                    'end_date',
                    models.DateField(help_text='The last day the campaign is active.'),
                ),
                (
                    'coupon',
                    models.CharField(
                        blank=True,
                        default='',
                        help_text='If coupon is empty, campaign is available to all users.',
                        max_length=255,
                    ),
                ),
                (
                    'discount_type',
                    waldur_mastermind.promotions.models.DiscountType(
                        choices=[
                            ('discount', 'Discount'),
                            ('special_price', 'Special price'),
                        ],
                        max_length=30,
                    ),
                ),
                ('discount', models.IntegerField()),
                ('stock', models.PositiveIntegerField(blank=True, null=True)),
                (
                    'months',
                    models.PositiveIntegerField(
                        default=1,
                        help_text='How many months in a row should the related service (when activated) get special deal (0 for indefinitely until active)',
                    ),
                ),
                ('auto_apply', models.BooleanField(blank=True, default=True)),
                (
                    'state',
                    django_fsm.FSMIntegerField(
                        choices=[(1, 'Draft'), (2, 'Active'), (3, 'Terminated')],
                        default=1,
                    ),
                ),
                (
                    'offerings',
                    models.ManyToManyField(
                        related_name='+',
                        to='marketplace.Offering',
                    ),
                ),
                (
                    'required_offerings',
                    models.ManyToManyField(
                        related_name='+',
                        to='marketplace.Offering',
                    ),
                ),
                (
                    'service_provider',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to='marketplace.serviceprovider',
                    ),
                ),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='DiscountedResource',
            fields=[
                (
                    'id',
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name='ID',
                    ),
                ),
                (
                    'created',
                    model_utils.fields.AutoCreatedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name='created',
                    ),
                ),
                (
                    'modified',
                    model_utils.fields.AutoLastModifiedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name='modified',
                    ),
                ),
                (
                    'campaign',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to='promotions.campaign',
                    ),
                ),
                (
                    'resource',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to='marketplace.resource',
                    ),
                ),
            ],
            options={
                'abstract': False,
            },
        ),
    ]
