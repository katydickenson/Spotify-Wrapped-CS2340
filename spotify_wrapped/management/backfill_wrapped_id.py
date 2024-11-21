from django.core.management.base import BaseCommand
from wrapped.models import SpotifyUser

class Command(BaseCommand):
    help = "Backfill WrappedID for existing Spotify users"

    def handle(self, *args, **kwargs):
        users = SpotifyUser.objects.all()
        for user in users:
            if user.user_name and user.spotify_id:
                wrapped_id = f"{user.user_name[:2].upper()}{user.spotify_id[-5:]}"
                user.wrapped_id = wrapped_id
                user.save()
                self.stdout.write(self.style.SUCCESS(f"Updated WrappedID for user {user.spotify_id}"))
        self.stdout.write(self.style.SUCCESS("Backfill complete."))
