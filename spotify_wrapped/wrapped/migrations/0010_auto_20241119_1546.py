from django.db import migrations, models

def populate_wrapped_ids(apps, schema_editor):
    SpotifyUser = apps.get_model('wrapped', 'SpotifyUser')
    for user in SpotifyUser.objects.all():
        if not user.wrapped_id:
            # Generate wrapped_id from username and spotify_id
            wrapped_id = f"{user.user_name[:2].upper()}{user.spotify_id[-5:]}"
            # Ensure uniqueness by adding numbers if necessary
            base_wrapped_id = wrapped_id
            counter = 1
            while SpotifyUser.objects.filter(wrapped_id=wrapped_id).exists():
                wrapped_id = f"{base_wrapped_id}{counter}"
                counter += 1
            user.wrapped_id = wrapped_id
            user.save()

class Migration(migrations.Migration):
    dependencies = [
        ('wrapped', '0009_alter_spotifyuser_wrapped_id'),  # Replace with your previous migration name
    ]

    operations = [
        # First ensure the field allows null values
        migrations.AlterField(
            model_name='spotifyuser',
            name='wrapped_id',
            field=models.CharField(max_length=10, null=True, blank=True),
        ),
        # Populate the null values
        migrations.RunPython(populate_wrapped_ids),
        # Make the field non-nullable and unique
        migrations.AlterField(
            model_name='spotifyuser',
            name='wrapped_id',
            field=models.CharField(max_length=10, unique=True),
        ),
    ]