from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import json
from .models import Feedback
from django.http import JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.conf import settings
import spotipy
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from spotipy.oauth2 import SpotifyOAuth
from functools import wraps
from django.contrib import messages
from .models import SpotifyUser, Feedback, SavedWrap
from django.http import JsonResponse
from django.db.models import Q
from django.urls import reverse
from django.http import HttpResponseRedirect
import logging
from django.core.exceptions import ObjectDoesNotExist
from .models import SpotifyAuth
from datetime import timedelta
from django.utils import timezone


logger = logging.getLogger(__name__)

def require_spotify_auth(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        access_token = request.session.get('access_token')

        if not access_token:
            request.session['next'] = request.get_full_path()
            return redirect('login')

        try:
            spotify = spotipy.Spotify(auth=access_token)
            spotify.me()
            return view_func(request, *args, **kwargs)
        except Exception as e:
            logger.warning(f"Spotify token validation failed: {str(e)}")
            request.session.flush()
            return redirect('login')

    return wrapper



def get_spotify_auth_manager(request):
    scope = 'user-read-private user-read-email user-top-read'
    state = f"st{request.session.session_key}"

    return SpotifyOAuth(
        client_id=settings.SPOTIFY_CLIENT_ID,
        client_secret=settings.SPOTIFY_CLIENT_SECRET,
        redirect_uri=settings.SPOTIFY_REDIRECT_URI,
        scope=scope,
        cache_handler=None,
        show_dialog=True,
        state=state
    )
@require_spotify_auth
def home(request):
    spotify = spotipy.Spotify(auth=request.session['access_token'])
    user_profile = spotify.me()
    user_name = spotify.me().get('display_name', 'User')

    profile_image = None
    if user_profile.get('images') and len(user_profile['images']) > 0:
        profile_image = user_profile['images'][0]['url']

    return render(request, 'wrapped/home.html', {
        'user_name': user_name,
        'profile_image': profile_image
    })


def login(request):
    spotify_keys = ['spotify_auth_cache', 'spotify_id', 'access_token',
                    'spotify_auth_state']
    for key in spotify_keys:
        request.session.pop(key, None)

    if not request.session.session_key:
        request.session.create()
    return render(request, 'wrapped/login.html')


def initiate_spotify_auth(request):
    request.session.flush()
    request.session.create()

    if not request.session.session_key:
        request.session.create()

    auth_manager = get_spotify_auth_manager(request)
    auth_url = auth_manager.get_authorize_url()

    request.session['spotify_auth_state'] = auth_manager.state
    request.session.modified = True

    logger.debug(f"Initiating auth with state: {auth_manager.state}")
    return redirect(auth_url)


def spotify_callback(request):
    error = request.GET.get('error')
    if error:
        logger.error(f"Spotify authentication error: {error}")
        return redirect('login')

    code = request.GET.get('code')
    state = request.GET.get('state')

    logger.debug(f"Received state: {state}")
    logger.debug(f"Session state: {request.session.get('spotify_auth_state')}")

    if not code:
        logger.error("CSRF token mismatch")
        return redirect('login')

    try:
        auth_manager = get_spotify_auth_manager(request)
        token_info = auth_manager.get_access_token(code, check_cache=False)

        logger.debug(f"Token info received: {bool(token_info)}")

        access_token = token_info.get('access_token')
        if not access_token:
            logger.error("No access token in token_info")
            raise ValueError("No access token returned")

        request.session['access_token'] = access_token
        request.session['refresh_token'] = token_info.get('refresh_token')
        request.session['token_expires_at'] = token_info.get('expires_at')
        request.session['spotify_auth_state'] = None
        request.session.modified = True

        spotify = spotipy.Spotify(auth=access_token)
        spotify_user = spotify.me()
        spotify_id = spotify_user.get('id')
        user_name = spotify_user.get('display_name', 'User')

        request.session['spotify_id'] = spotify_id

        user, created = SpotifyUser.objects.get_or_create(
            spotify_id=spotify_id,
            defaults={'user_name': user_name}
        )

        auth, created = SpotifyAuth.objects.update_or_create(
            user=user,
            defaults={
                'access_token': access_token,
                'refresh_token': token_info.get('refresh_token'),
                'token_expiry': timezone.now() + timedelta(seconds=token_info.get('expires_in', 3600))
            }
        )
        logger.info(f"Saved auth token for user: {spotify_id}")
        

        next_url = request.session.pop('next', 'home')
        return redirect(next_url)

    except Exception as e:
        logger.error(f"Error during Spotify callback: {str(e)}")
        return redirect('login')


def logout(request):
    spotify_keys = ['spotify_auth_cache', 'spotify_id', 'access_token',
                    'spotify_auth_state']
    for key in spotify_keys:
        request.session.pop(key, None)

    request.session.modified = True
    return redirect('login')

def settingshome(request):
    try:
        spotify = spotipy.Spotify(auth=request.session['access_token'])
        user_profile = spotify.me()
        user_name = user_profile.get('display_name', 'User')
        spotify_id = user_profile.get('id')

        profile_image = None
        if user_profile.get('images') and len(user_profile['images']) > 0:
            profile_image = user_profile['images'][0]['url']

        return render(request, 'wrapped/settingsHome.html', {
            'user_name': user_name,
            'profile_image': profile_image,
            'spotify_id': spotify_id,
        })

    except Exception as e:
        logger.error(f"Error in addfriends view: {str(e)}")
        return redirect('home')

def contactus(request):
    try:
        spotify = spotipy.Spotify(auth=request.session['access_token'])
        user_profile = spotify.me()
        user_name = user_profile.get('display_name', 'User')
        spotify_id = user_profile.get('id')

        profile_image = None
        if user_profile.get('images') and len(user_profile['images']) > 0:
            profile_image = user_profile['images'][0]['url']

        return render(request, 'wrapped/contactUs.html', {
            'user_name': user_name,
            'profile_image': profile_image,
            'spotify_id': spotify_id,
        })

    except Exception as e:
        logger.error(f"Error in addfriends view: {str(e)}")
        return redirect('home')


@require_spotify_auth
def addfriends(request):
    try:
        spotify = spotipy.Spotify(auth=request.session['access_token'])
        user_profile = spotify.me()
        user_name = user_profile.get('display_name', 'User')
        spotify_id = user_profile.get('id')

        all_users = SpotifyUser.objects.all()
        logger.debug(f"Total users in database: {all_users.count()}")
        for user in all_users:
            logger.debug(f"User in DB: {user.spotify_id} - {user.user_name}")

        profile_image = None
        if user_profile.get('images') and len(user_profile['images']) > 0:
            profile_image = user_profile['images'][0]['url']

        return render(request, 'wrapped/addFriends.html', {
            'user_name': user_name,
            'profile_image': profile_image,
            'spotify_id': spotify_id,
        })

    except Exception as e:
        logger.error(f"Error in addfriends view: {str(e)}")
        return redirect('home')

def delete_account(request):
    if request.method == 'POST':
        spotify_id = request.session.get('spotify_id')
        logger.debug(
            f"Attempting to delete SpotifyUser account for spotify_id: {spotify_id}")

        if spotify_id:
            try:
                spotify_user = SpotifyUser.objects.get(spotify_id=spotify_id)

                logger.info(
                    f"Deleting SpotifyUser: {spotify_user.user_name} (ID: {spotify_user.spotify_id})")

                spotify_user.delete()

                for key in list(request.session.keys()):
                    if key in ['spotify_id', 'access_token']:
                        del request.session[key]

                messages.success(request,
                                 "Your Spotify account and associated data have been permanently deleted.")
                return redirect('login')

            except SpotifyUser.DoesNotExist:
                logger.error(
                    f"Failed to delete account: SpotifyUser with ID {spotify_id} not found")
                messages.error(request,
                               "Could not delete account: user not found.")
                return redirect('settingsHome')
            except Exception as e:
                logger.error(f"Error deleting account: {str(e)}")
                messages.error(request,
                               "An error occurred while deleting your account.")
                return redirect('settingsHome')
        else:
            logger.error("No spotify_id found in session")
            messages.error(request,
                           "Could not delete account: no user ID found in session.")
            return redirect('settingsHome')

    return redirect('settingsHome')


def require_spotify_auth(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        access_token = request.session.get('access_token')

        # If token exists in session, verify it's still valid
        if access_token:
            try:
                spotify = spotipy.Spotify(auth=access_token)
                spotify.me()  # Verify token is valid
                return view_func(request, *args, **kwargs)
            except Exception as e:
                logger.warning(f"Spotify token validation failed: {str(e)}")
                # Only clear Spotify-related session data
                spotify_keys = ['spotify_auth_cache', 'spotify_id',
                                'access_token', 'spotify_auth_state']
                for key in spotify_keys:
                    request.session.pop(key, None)
                request.session.modified = True
                return redirect('login')

        # If no token, store the requested URL and redirect to login
        request.session['next'] = request.get_full_path()
        return redirect('login')

    return wrapper
"""
    return render(request, 'wrapped/addFriends.html', {
        'user_name': user_name,
        'profile_image': profile_image,
        'spotify_id': spotify_id,
        'friends': friends,
        'has_friends': friends.exists()
    })
"""


def remove_friend(request):
    if request.method == 'POST':
        friend_id = request.POST.get('friend_id')
        try:
            current_user = SpotifyUser.objects.get(
                spotify_id=request.session.get('spotify_id'))
            friend_user = SpotifyUser.objects.get(spotify_id=friend_id)

            # Remove friend relationship
            current_user.friends.remove(friend_user)
            friend_user.friends.remove(
                current_user)  # Remove bidirectional relationship

            messages.success(request,
                             f"Successfully removed {friend_user.user_name} from friends.")

        except SpotifyUser.DoesNotExist:
            messages.error(request, "User not found.")
            logger.error(
                f"Failed to remove friend: User not found with ID {friend_id}")
        except Exception as e:
            messages.error(request, "An error occurred while removing friend.")
            logger.error(f"Error removing friend: {str(e)}")

    return redirect('addFriends')  # Update this line to match the URL name

@csrf_exempt
@require_http_methods(["POST"])
def submit_feedback(request):
    try:
        data = json.loads(request.body)
        feedback = Feedback.objects.create(
            name=data.get('name'),
            email=data.get('email'),
            message=data.get('message')
        )
        return JsonResponse({
            'status': 'success',
            'message': 'Feedback submitted successfully'
        })
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=400)
def add_friend(request):
    if request.method == 'POST':
        friend_id = request.POST.get('friend_id')
        try:
            current_user = SpotifyUser.objects.get(
                spotify_id=request.session.get('spotify_id'))
            friend_user = SpotifyUser.objects.get(spotify_id=friend_id)

            # Check if already friends
            if friend_user in current_user.friends.all():
                return JsonResponse({
                    'success': False,
                    'error': 'Already friends with this user'
                })

            # Add friend relationship
            current_user.friends.add(friend_user)
            friend_user.friends.add(current_user)

            return JsonResponse({
                'success': True,
                'message': f"Successfully added {friend_user.user_name}",
                'friend': {
                    'id': friend_user.spotify_id,
                    'name': friend_user.user_name,
                    'profile_image': friend_user.profile_image
                }
            })

        except SpotifyUser.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': "User not found with that Spotify ID."
            })
        except Exception as e:
            logger.error(f"Error adding friend: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': "An error occurred while adding friend."
            })

    return JsonResponse({'success': False, 'error': 'Invalid request method'})



@csrf_exempt  # Add this decorator for search functionality
@require_spotify_auth
def search_users(request):
    try:
        query = request.GET.get('query', '').strip()
        current_user_id = request.session.get('spotify_id')

        if len(query) >= 1:
            # Search for users
            users = SpotifyUser.objects.exclude(
                spotify_id=current_user_id).filter(
                spotify_id__icontains=query
            )[:5]

            results = []
            for user in users:
                results.append({
                    'id': user.spotify_id,
                    'name': user.user_name,
                    'profile_image': user.profile_image
                })

            return JsonResponse({
                'success': True,
                'results': results
            })

        return JsonResponse({
            'success': True,
            'results': []
        })

    except Exception as e:
        logger.error(f"Search error: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Search failed'
        }, status=500)

    
@require_spotify_auth
def get_friends(request):
    try:
        current_user = SpotifyUser.objects.get(
            spotify_id=request.session.get('spotify_id'))
        friends = current_user.friends.all()

        friends_data = [{
            'spotify_id': friend.spotify_id,
            'user_name': friend.user_name,
            'profile_image': friend.profile_image if friend.profile_image else None
        } for friend in friends]

        return JsonResponse({
            'success': True,
            'friends': friends_data
        })
    except Exception as e:
        logger.error(f"Error getting friends: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to get friends list'
        }, status=500)

@require_spotify_auth
def addfriends(request):
    try:
        spotify = spotipy.Spotify(auth=request.session['access_token'])
        user_profile = spotify.me()
        user_name = user_profile.get('display_name', 'User')
        spotify_id = user_profile.get('id')

        # Get profile image URL
        profile_image = None
        if user_profile.get('images') and len(user_profile['images']) > 0:
            profile_image = user_profile['images'][0]['url']

        # Get current user's friends
        current_user = SpotifyUser.objects.get(spotify_id=spotify_id)
        friends = current_user.friends.all()

        return render(request, 'wrapped/addFriends.html', {
            'user_name': user_name,
            'profile_image': profile_image,
            'spotify_id': spotify_id,
            'friends': friends,
            'has_friends': friends.exists()
        })

    except Exception as e:
        logger.error(f"Error in addfriends view: {str(e)}")
        return redirect('login')
    
def wrapped_filters(request):
    try:
        if request.method == 'POST':
            time_range = request.POST.get('time_range')
            holiday_theme = request.POST.get('holiday_theme')
            wrapped_name = request.POST.get('wrapped_name')

            request.session['selected_time_range'] = time_range
            request.session['holiday_theme'] = holiday_theme
            request.session['wrapped_name'] = wrapped_name
            return redirect('wrapped_results')

        spotify = spotipy.Spotify(auth=request.session['access_token'])
        user_profile = spotify.me()
        user_name = user_profile.get('display_name', 'User')
        spotify_id = user_profile.get('id')

        profile_image = None
        if user_profile.get('images') and len(user_profile['images']) > 0:
            profile_image = user_profile['images'][0]['url']

        return render(request, 'wrapped/wrapped_filters.html', {
            'user_name': user_name,
            'profile_image': profile_image,
            'spotify_id': spotify_id,
        })
    except Exception as e:
        logger.error(f"Error in addfriends view: {str(e)}")
        return redirect('home')

@require_spotify_auth
def wrapped_results(request):
    if 'access_token' not in request.session:
        return redirect('login')
        
    spotify = spotipy.Spotify(auth=request.session['access_token'])
    user_profile = spotify.me()
    spotify_id = user_profile['id']
    spotify_user, created = SpotifyUser.objects.get_or_create(
        spotify_id=spotify_id,
        defaults={'user_name': user_profile.get('display_name', 'User')}
    )
    
    time_range = request.session.get('selected_time_range', '1month')
    holiday_theme = request.session.get('holiday_theme') 
    
    spotify_time_range = {
        '1month': 'short_term',
        '6months': 'medium_term',
        '1year': 'long_term'
    }.get(time_range, 'medium_term')

    # Get all tracks first
    top_tracks = spotify.current_user_top_tracks(
        limit=50,
        offset=0,
        time_range=spotify_time_range,
    )
    
    tracks_data = []
    genre_dict = {}
    genre_dict['december_break_genres'] = ['holidays', 'gospel', 'children', 'jazz', 'classical', 'piano', 'soft rock', 'kentucky indie']
    genre_dict['valentines_genres'] = ['romance', 'r-n-b', 'soul', 'singer-songwriter', 'pop']
    genre_dict['fourth_genres'] = ['rock', 'country', 'summer', 'dance', 'contemporary country', 'party', 'kentucky indie']
    genre_dict['december_break_genres_broad'] = ['singer', 'singer-songwriter', 'folk', 'movies', 'opera', 'show-tunes', 'soul', 'folk', 'art pop']
    genre_dict['valentines_genres_broad'] = ['jazz', 'acoustic', 'latin', 'piano', 'indie-pop']
    genre_dict['fourth_genres_broad'] = ['indie', 'funk', 'disco', 'blues', 'folk']

    print(spotify.recommendation_genre_seeds())
    # Process tracks based on theme
    if holiday_theme != 'none':
        curr_genres = genre_dict[holiday_theme + "_genres"]
        for track in top_tracks['items']:
            track_data = {
                'name': track['name'],
                'artist': track['artists'][0]['name'],
                'image_url': track['album']['images'][0]['url'] if track['album']['images'] else None,
                'preview_url': track['preview_url']
            }
            artist_id = track['artists'][0]['id']
            artist_info = spotify.artist(artist_id)
            artist_genres = artist_info['genres']
            check = False
            for genre in artist_genres:
                if genre in curr_genres:
                    check = True
                    break
            if check:
                tracks_data.append(track_data)
            if len(tracks_data) >= 10:
                break

        if len(tracks_data) == 0:
            curr_genres = genre_dict[holiday_theme + "_genres_broad"]
            for track in top_tracks['items']:
                track_data = {
                    'name': track['name'],
                    'artist': track['artists'][0]['name'],
                    'image_url': track['album']['images'][0]['url'] if track['album']['images'] else None,
                    'preview_url': track['preview_url']
                }
                artist_id = track['artists'][0]['id']
                artist_info = spotify.artist(artist_id)
                artist_genres = artist_info['genres']
                check = False
                for genre in artist_genres:
                    if genre in curr_genres:
                        check = True
                        break
                if check:
                    tracks_data.append(track_data)
                if len(tracks_data) >= 10:
                    break
    else:
        for track in top_tracks['items']:
            track_data = {
                'name': track['name'],
                'artist': track['artists'][0]['name'],
                'image_url': track['album']['images'][0]['url'] if track['album']['images'] else None,
                'preview_url': track['preview_url']
            }
            tracks_data.append(track_data)
            if len(tracks_data) >= 10:
                break

    # Get artists
    top_artists = spotify.current_user_top_artists(
        limit=50,
        offset=0,
        time_range=spotify_time_range
    )
    
    artists_data = []
    genre_count = {}

    if holiday_theme != 'none':
        curr_genres = genre_dict[holiday_theme + "_genres"]
        for artist in top_artists['items']:
            genres = artist['genres']
            artist_data = {
                'name': artist['name'],
                'image_url': artist['images'][0]['url'] if artist['images'] else None,
                'genres': genres
            }
            check = False
            for genre in genres:
                if genre in curr_genres:
                    check = True
                    genre_count[genre] = genre_count.get(genre, 0) + 1
                    break
            if check:
                artists_data.append(artist_data)
            if len(artists_data) >= 10:
                break

        if len(artists_data) == 0:
            curr_genres = genre_dict[holiday_theme + "_genres_broad"]
            for artist in top_artists['items']:
                genres = artist['genres']
                artist_data = {
                    'name': artist['name'],
                    'image_url': artist['images'][0]['url'] if artist['images'] else None,
                    'genres': genres
                }
                check = False
                for genre in genres:
                    if genre in curr_genres:
                        check = True
                        genre_count[genre] = genre_count.get(genre, 0) + 1
                        break
                if check:
                    artists_data.append(artist_data)
                if len(tracks_data) >= 10:
                    break
    else:
        for artist in top_artists['items']:
            genres = artist['genres']
            artist_data = {
                'name': artist['name'],
                'image_url': artist['images'][0]['url'] if artist['images'] else None,
                'genres': genres
            }
            artists_data.append(artist_data)
            genre_count[genres[0]] = genre_count.get(genres[0], 0) + 1

            if len(artists_data) >= 10:
                break

    # Format genres
    top_genres = sorted(genre_count.items(), key=lambda x: x[1], reverse=True)[:5]
    formatted_genres = [
        {
            'name': ' '.join(word.capitalize() for word in genre.replace('-', ' ').split()),
            'count': count
        } for genre, count in top_genres
    ]

    # Save wrap
    wrap = SavedWrap.objects.create(
        user=spotify_user,
        title=request.session.get('wrapped_name', 'My Wrap'),
        tracks_data=tracks_data,
        artists_data=artists_data,  # Use the themed or regular artist list
        genres_data=formatted_genres,
        time_range=time_range,
        holiday_theme=holiday_theme
    )

    return render(request, 'wrapped/wrapped_results.html', {
        'tracks': tracks_data,
        'artists': artists_data,
        'genres': formatted_genres,
        'time_range': time_range,
        'holiday_theme': holiday_theme,
        'user_name': user_profile['display_name'],
        'wrapped_name': request.session.get('wrapped_name', '')
    })

@require_spotify_auth
def past_spotify_wraps(request):
    try:
        spotify = spotipy.Spotify(auth=request.session['access_token'])
        spotify_id = spotify.me()['id']
        spotify_user = SpotifyUser.objects.get(spotify_id=spotify_id)
        
        print(f"Looking for wraps for user: {spotify_id}")
        wraps = SavedWrap.objects.filter(user=spotify_user).order_by('-created_at')
        print(f"Found {wraps.count()} wraps")
        
        return render(request, 'wrapped/past_spotify_wraps.html', {
            'wraps': wraps,
            'user_name': spotify_user.user_name,
            'profile_image': spotify.me()['images'][0]['url'] if spotify.me()['images'] else None,
        })
    except Exception as e:
        print(f"Error in past_spotify_wraps: {str(e)}")
        return redirect('login')

@require_spotify_auth
def view_saved_wrap(request, wrap_id):
    try:
        spotify = spotipy.Spotify(auth=request.session['access_token'])
        spotify_id = spotify.me()['id']
        spotify_user = SpotifyUser.objects.get(spotify_id=spotify_id)
        
        wrap = get_object_or_404(SavedWrap, id=wrap_id, user=spotify_user)
        
        return render(request, 'wrapped/view_saved_wrap.html', {
            'wrap': wrap,
            'user_name': spotify_user.user_name,
            'profile_image': spotify.me()['images'][0]['url'] if spotify.me()['images'] else None,
        })
    except Exception as e:
        logger.error(f"Error viewing saved wrap: {str(e)}")
        return redirect('past_spotify_wraps')
    
@require_spotify_auth
def delete_wrap(request, wrap_id):
    if request.method == 'POST':
        spotify = spotipy.Spotify(auth=request.session['access_token'])
        spotify_id = spotify.me()['id']
        spotify_user = SpotifyUser.objects.get(spotify_id=spotify_id)
        
        wrap = get_object_or_404(SavedWrap, id=wrap_id, user=spotify_user)
        wrap.delete()
    
    return redirect('past_spotify_wraps')

@require_spotify_auth
def delete_all_wraps(request):
    if request.method == 'POST':
        spotify = spotipy.Spotify(auth=request.session['access_token'])
        spotify_id = spotify.me()['id']
        spotify_user = SpotifyUser.objects.get(spotify_id=spotify_id)
        
        SavedWrap.objects.filter(user=spotify_user).delete()
    
    return redirect('past_spotify_wraps')
@require_spotify_auth
def duo_wrapped(request):
    try:
        spotify = spotipy.Spotify(auth=request.session['access_token'])
        current_user = SpotifyUser.objects.get(spotify_id=request.session.get('spotify_id'))

        friends = current_user.friends.all()
        
        return render(request, 'wrapped/duo_wrapped.html', {
            'friends': friends,
            'user_name': spotify.me()['display_name'],
            'profile_image': spotify.me()['images'][0]['url'] if spotify.me()['images'] else None,
        })
    except Exception as e:
        logger.error(f"Error in duo_wrapped view: {str(e)}")
        return redirect('home')

@require_spotify_auth
def duo_comparison(request, friend_id):
    try:
        # Get current user's Spotify client
        current_user = SpotifyUser.objects.get(spotify_id=request.session.get('spotify_id'))
        current_user_spotify = spotipy.Spotify(auth=request.session['access_token'])
        
        # Get current user's top tracks so that nxt page renders
        user_top_tracks = current_user_spotify.current_user_top_tracks(
                limit=5,
                offset=0,
                time_range='medium_term'
            )['items']
        
        try:
            friend = SpotifyUser.objects.get(spotify_id=friend_id)
            
            # Even if friend auth doesn't exist, we'll still render the page
            try:
                friend_auth = SpotifyAuth.objects.get(user=friend)
                if friend_auth.is_token_valid():
                    friend_spotify = spotipy.Spotify(auth=friend_auth.access_token)
                    friend_top_tracks = friend_spotify.current_user_top_tracks(
                        limit=5,
                        offset=0,
                        time_range='medium_term'
                    )['items']
                else:
                    friend_top_tracks = None
            except SpotifyAuth.DoesNotExist:
                friend_top_tracks = None
                logger.info(f"Friend {friend_id} needs to authenticate")
            
            # Always render the page, with or without friend's tracks
            return render(request, 'wrapped/duo_comparison.html', {
                'user': current_user,
                'friend': friend,
                'user_songs': user_top_tracks,
                'friend_songs': friend_top_tracks,
                'friend_needs_auth': friend_top_tracks is None,
                'message': "Your friend needs to log in to enable comparison."
            })
            
        except SpotifyUser.DoesNotExist:
            messages.error(request, "Friend not found.")
            return redirect('duo_wrapped')
            
    except Exception as e:
        logger.error(f"Error in duo_comparison: {str(e)}")
        messages.error(request, "An error occurred while creating the duo comparison.")
        return redirect('duo_wrapped')