# Generated by Django 5.0.1 on 2024-05-03 12:18

import datetime
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0022_alter_logunit_called_at_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="logunit",
            name="called_at",
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
        migrations.AlterField(
            model_name="onetimepassword",
            name="created_at",
            field=models.DateTimeField(
                default=datetime.datetime(
                    2024, 5, 3, 12, 18, 14, 297785, tzinfo=datetime.timezone.utc
                )
            ),
        ),
    ]
