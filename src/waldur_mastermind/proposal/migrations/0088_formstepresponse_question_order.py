from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("proposal", "0054_call_formbricks_flow_key_formstepresponse"),
    ]

    operations = [
        migrations.AddField(
            model_name="formstepresponse",
            name="question_order",
            field=models.JSONField(blank=True, default=list),
        ),
    ]
