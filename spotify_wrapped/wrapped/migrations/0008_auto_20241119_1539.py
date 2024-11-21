from django.db import migrations

def generate_wrapped_ids(apps, schema_editor):
    SpotifyUser = apps.get_model('wrapped', 'SpotifyUser')
    for user in SpotifyUser.objects.all():
        if not user.wrapped_id:
            user.wrapped_id = f"{user.user_name[:2].upper()}{user.spotify_id[-5:]}"
            user.save()

def reverse_func(apps, schema_editor):
    pass

class Migration(migrations.Migration):

    dependencies = [
        ('wrapped', '0007_spotifyuser_wrapped_id'),
    ]

    operations = [
        migrations.RunPython(generate_wrapped_ids, reverse_func),
    ]