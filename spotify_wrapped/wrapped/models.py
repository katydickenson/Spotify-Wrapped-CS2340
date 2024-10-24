from django.db import models

# Create your models here.
from django.db import models

class SpotifyUser(models.Model):
    spotify_id = models.CharField(max_length=255, primary_key=True)  # Set as primary key
    user_name = models.CharField(max_length=255)  # User's display name from Spotify
    last_spotify_wrapped = models.JSONField(default=dict)  # To store the last Spotify wrapped data

    def __str__(self):
        return self.user_name
