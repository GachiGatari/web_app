# Generated by Django 5.0.1 on 2024-04-20 08:57

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0012_alter_onetimepassword_created_at_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="onetimepassword",
            name="created_at",
            field=models.DateTimeField(
                default=datetime.datetime(
                    2024, 4, 20, 8, 57, 48, 973611, tzinfo=datetime.timezone.utc
                )
            ),
        ),
        migrations.AlterField(
            model_name="permission",
            name="name",
            field=models.CharField(max_length=100),
        ),
        migrations.AlterField(
            model_name="role",
            name="name",
            field=models.CharField(max_length=100),
        ),
        migrations.AlterField(
            model_name="role",
            name="permissions",
            field=models.ManyToManyField(to="users.permission"),
        ),
    ]
