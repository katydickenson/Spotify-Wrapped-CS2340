from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.login, name='login'),
    path('spotify-auth/', views.initiate_spotify_auth, name='spotify_login'),  # This matches the URL in your template
    path('settingsHome/', views.settingshome, name='settingsHome'),
    path('contactUs/', views.contactus, name='contactUs'),
    path('callback/', views.spotify_callback, name='spotify_callback'),
    path('logout/', views.logout, name='logout'),
    path('delete_account/', views.delete_account, name='delete_account'),
    path('addFriends/', views.addfriends, name='addFriends'),
    path('add-friend/', views.add_friend, name='add_friend'),
    path('remove-friend/', views.remove_friend, name='remove_friend'),
    path('search-users/', views.search_users, name='search_users'),
    path('get-friends/', views.get_friends, name='get_friends'),
    path('api/submit-feedback/', views.submit_feedback, name='submit_feedback'),
    path('wrapped-filters/', views.wrapped_filters, name='wrapped_filters'),
    path('wrapped-results/', views.wrapped_results, name='wrapped_results'),
]