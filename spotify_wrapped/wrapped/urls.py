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
    path('past-spotify-wraps/', views.past_spotify_wraps, name='past_spotify_wraps'),
    path('view-saved-wrap/<int:wrap_id>/', views.view_saved_wrap, name='view_saved_wrap'),
    path('delete-wrap/<int:wrap_id>/', views.delete_wrap, name='delete_wrap'),
    path('delete-all-wraps/', views.delete_all_wraps, name='delete_all_wraps'),
    path('duo-wrapped/', views.duo_wrapped, name='duo_wrapped'),
    path('duo-comparison/<str:friend_id>/', views.duo_comparison, name='duo_comparison'),
]