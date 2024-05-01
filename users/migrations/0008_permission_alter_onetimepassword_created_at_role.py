# Generated by Django 5.0.1 on 2024-04-20 08:44

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0007_rename_user_agent_onetimepassword_session_id_and_more"),
    ]

    operations = [
        migrations.CreateModel(
            name="Permission",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("name", models.CharField(max_length=100, unique=True)),
            ],
        ),
        migrations.AlterField(
            model_name="onetimepassword",
            name="created_at",
            field=models.DateTimeField(
                default=datetime.datetime(
                    2024, 4, 20, 8, 44, 25, 556046, tzinfo=datetime.timezone.utc
                )
            ),
        ),
        migrations.CreateModel(
            name="Role",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("name", models.CharField(max_length=100, unique=True)),
                ("permissions", models.ManyToManyField(to="users.permission")),
            ],
        ),
    ]