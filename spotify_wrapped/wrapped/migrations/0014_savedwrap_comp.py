# Generated by Django 5.1.2 on 2024-11-21 23:30

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("wrapped", "0013_remove_spotifyuser_email_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="savedwrap",
            name="comp",
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]
