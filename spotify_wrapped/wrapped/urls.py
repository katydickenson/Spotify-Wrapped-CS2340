from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.login, name='login'),
    path('spotify-auth/', views.initiate_spotify_auth, name='spotify_login'),  # This matches the URL in your template
    path('callback/', views.spotify_callback, name='spotify_callback'),
    path('logout/', views.logout, name='logout'),
]