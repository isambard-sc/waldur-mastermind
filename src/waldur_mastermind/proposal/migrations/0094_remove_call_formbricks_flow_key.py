from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("proposal", "0093_seed_formbricks_flows"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="call",
            name="formbricks_flow_key",
        ),
    ]
