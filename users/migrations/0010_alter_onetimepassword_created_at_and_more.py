# Generated by Django 5.0.1 on 2024-04-20 08:51

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0009_alter_onetimepassword_created_at_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="onetimepassword",
            name="created_at",
            field=models.DateTimeField(
                default=datetime.datetime(
                    2024, 4, 20, 8, 51, 47, 912956, tzinfo=datetime.timezone.utc
                )
            ),
        ),
        migrations.AlterField(
            model_name="role",
            name="permissions",
            field=models.ManyToManyField(to="users.permission"),
        ),
    ]
