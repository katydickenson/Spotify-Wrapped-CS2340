from django.contrib import admin
from .models import SpotifyUser

@admin.register(SpotifyUser)
class SpotifyUserAdmin(admin.ModelAdmin):
    list_display = ('spotify_id', 'user_name')  # Customize the fields you want to display

