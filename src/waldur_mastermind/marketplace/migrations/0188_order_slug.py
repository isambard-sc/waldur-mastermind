from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("marketplace", "0187_alter_categorycomponent_description_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="order",
            name="slug",
            field=models.SlugField(blank=True, editable=False),
        ),
    ]
