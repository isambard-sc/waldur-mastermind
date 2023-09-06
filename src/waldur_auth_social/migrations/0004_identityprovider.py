# Generated by Django 3.2.20 on 2023-08-04 07:56

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('waldur_auth_social', '0003_delete_remoteeduteamsuser'),
    ]

    operations = [
        migrations.CreateModel(
            name='IdentityProvider',
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
                ('provider', models.CharField(max_length=32, unique=True)),
                ('is_active', models.BooleanField(default=True)),
                (
                    'client_id',
                    models.CharField(
                        help_text='ID of application used for OAuth authentication.',
                        max_length=200,
                    ),
                ),
                (
                    'client_secret',
                    models.CharField(
                        help_text='Application secret key.', max_length=200
                    ),
                ),
                ('verify_ssl', models.BooleanField(default=True)),
                (
                    'discovery_url',
                    models.CharField(
                        max_length=200, help_text='The endpoint for endpoint discovery.'
                    ),
                ),
                (
                    'userinfo_url',
                    models.CharField(
                        max_length=200, help_text='The endpoint for fetching user info.'
                    ),
                ),
                (
                    'token_url',
                    models.CharField(
                        max_length=200,
                        help_text='The endpoint for obtaining auth token.',
                    ),
                ),
                (
                    'auth_url',
                    models.CharField(
                        max_length=200,
                        help_text='The endpoint for authorization request flow.',
                    ),
                ),
                (
                    'label',
                    models.CharField(
                        help_text='Human-readable identity provider is label.',
                        max_length=200,
                    ),
                ),
                (
                    'management_url',
                    models.CharField(
                        max_length=200,
                        blank=True,
                        help_text='The endpoint for user details management.',
                    ),
                ),
                ('protected_fields', models.JSONField(default=list)),
            ],
        ),
    ]