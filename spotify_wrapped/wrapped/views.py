from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import json

from spotipy.client import Spotify

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
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.urls import reverse
from django.http import HttpResponseRedirect
import logging
from django.core.exceptions import ObjectDoesNotExist
from .models import SpotifyAuth
from datetime import timedelta
from django.utils import timezone
import time


logger = logging.getLogger(__name__)


def require_spotify_auth(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        access_token = request.session.get('access_token')
        expires_at = request.session.get('token_expires_at')
        refresh_token = request.session.get('refresh_token')

        if not access_token:
            logger.debug("No access token found, redirecting to login")
            request.session['next'] = request.get_full_path()
            return redirect('login')

        try:
            # Check if token is expired
            if expires_at and time.time() > expires_at:
                if refresh_token:
                    logger.debug("Token expired, attempting refresh")
                    auth_manager = get_spotify_auth_manager(request)
                    token_info = auth_manager.refresh_access_token(
                        refresh_token)

                    # Update session with new token info
                    request.session['access_token'] = token_info['access_token']
                    request.session['token_expires_at'] = token_info[
                        'expires_at']
                    request.session.modified = True
                    access_token = token_info['access_token']
                else:
                    logger.debug("No refresh token available")
                    return redirect('login')

            # Verify token is valid
            spotify = spotipy.Spotify(auth=access_token)
            spotify.me()
            return view_func(request, *args, **kwargs)

        except Exception as e:
            logger.warning(f"Spotify token validation failed: {str(e)}")
            # Clear only Spotify-related session data
            spotify_keys = ['spotify_auth_cache', 'spotify_id', 'access_token',
                            'spotify_auth_state', 'refresh_token',
                            'token_expires_at']
            for key in spotify_keys:
                request.session.pop(key, None)
            request.session.modified = True

            # Store the current path before redirecting
            request.session['next'] = request.get_full_path()
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

"""
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
"""
@require_spotify_auth
def home(request):
    spotify = spotipy.Spotify(auth=request.session['access_token'])
    user_profile = spotify.me()
    user_name = user_profile.get('display_name', 'User')

    profile_image = None
    if user_profile.get('images') and len(user_profile['images']) > 0:
        profile_image = user_profile['images'][0]['url']

    return render(request, 'wrapped/home.html', {
        'user_name': user_name,
        'profile_image': profile_image
    })

def login(request):
    # Clear previous Spotify session data
    spotify_keys = ['spotify_auth_cache', 'spotify_id', 'access_token', 'spotify_auth_state']
    for key in spotify_keys:
        request.session.pop(key, None)

    # Ensure session is created if it doesn't exist
    if not request.session.session_key:
        request.session.create()

    return render(request, 'wrapped/login.html')



"""def initiate_spotify_auth(request):
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
"""


def initiate_spotify_auth(request):
    # Create a new session if one doesn't exist
    if not request.session.session_key:
        request.session.create()

    # Only clear Spotify-related session data
    spotify_keys = ['spotify_auth_cache', 'spotify_id', 'access_token',
                    'spotify_auth_state', 'refresh_token', 'token_expires_at']
    for key in spotify_keys:
        request.session.pop(key, None)

    auth_manager = get_spotify_auth_manager(request)
    auth_url = auth_manager.get_authorize_url()

    # Store state for CSRF protection
    request.session['spotify_auth_state'] = auth_manager.state
    request.session.modified = True

    logger.debug(f"Initiating auth with state: {auth_manager.state}")
    return redirect(auth_url)


def clear_spotify_session_data(request):
    """Helper function to clear Spotify-specific session data without affecting other session data."""
    spotify_keys = ['spotify_auth_cache', 'spotify_id', 'access_token', 'refresh_token', 'spotify_auth_state']
    for key in spotify_keys:
        request.session.pop(key, None)
    request.session.modified = True

def get_spotify_auth_manager(request):
    scope = 'user-read-private user-read-email user-top-read'
    state = f"st{request.session.session_key}"

    return SpotifyOAuth(
        client_id=settings.SPOTIFY_CLIENT_ID,
        client_secret=settings.SPOTIFY_CLIENT_SECRET,
        redirect_uri=settings.SPOTIFY_REDIRECT_URI,
        scope=scope,
        cache_path=None,
        show_dialog=True,
        state=state
    )

"""def spotify_callback(request):
    error = request.GET.get('error')
    if error:
        logger.error(f"Spotify authentication error: {error}")
        return redirect('login')

    code = request.GET.get('code')
    state = request.GET.get('state')

    if not code or state != request.session.get('spotify_auth_state'):
        logger.error("CSRF token mismatch or no authorization code received")
        return redirect('login')

    try:
        auth_manager = get_spotify_auth_manager(request)
        token_info = auth_manager.get_access_token(code)

        access_token = token_info.get('access_token')
        if not access_token:
            raise ValueError("No access token returned")

        # Store tokens in session
        request.session['access_token'] = access_token
        request.session['refresh_token'] = token_info.get('refresh_token')
        request.session['token_expires_at'] = token_info.get('expires_at')
        request.session['spotify_auth_state'] = None
        request.session.modified = True

        next_url = request.session.get('next', 'home')  # Don't pop yet; just get it.
        return redirect(next_url)

    except Exception as e:
        logger.error(f"Error during Spotify callback: {str(e)}")
        return redirect('login')
"""


def spotify_callback(request):
    error = request.GET.get('error')
    if error:
        logger.error(f"Spotify authentication error: {error}")
        return redirect('login')

    code = request.GET.get('code')

    if not code:
        logger.error(
            "CSRF token mismatch or no authorization code received")
        return redirect('login')

    try:
        auth_manager = get_spotify_auth_manager(request)
        token_info = auth_manager.get_access_token(code)

        access_token = token_info.get('access_token')
        if not access_token:
            raise ValueError("No access token returned")

        # Store all token information
        request.session['access_token'] = access_token
        request.session['refresh_token'] = token_info.get('refresh_token')
        request.session['token_expires_at'] = token_info.get('expires_at')

        # Get user information using the token
        spotify = spotipy.Spotify(auth=access_token)
        spotify_user = spotify.me()
        spotify_id = spotify_user.get('id')
        user_name = spotify_user.get('display_name', 'User')
        profile_image = spotify_user.get('images')[0]['url'] if spotify_user.get('images') else None

        # Generate WrappedID
        wrapped_id = f"{user_name[:2].upper()}{spotify_id[-5:]}" if user_name else f"WR{spotify_id[-5:]}"

        # Store spotify_id in session
        request.session['spotify_id'] = spotify_id

        # Create or update user in database
        user, created = SpotifyUser.objects.update_or_create(
            spotify_id=spotify_id,
            defaults={
                'user_name': user_name,
                'profile_image': profile_image,
                'wrapped_id': wrapped_id  # Add WrappedID to the database
            }
        )

        # Ensure session is saved
        request.session.modified = True

        # Clear the auth state after successful authentication
        request.session['spotify_auth_state'] = None

        # Get the next URL or default to home
        next_url = request.session.get('next', 'home')

        logger.info(
            f"Authentication successful for user {spotify_id}, redirecting to {next_url}")
        return redirect(next_url)

    except Exception as e:
        logger.error(f"Error during Spotify callback: {str(e)}")
        return redirect('login')



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

"""
def require_spotify_auth(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        access_token = request.session.get('access_token')
        expires_at = request.session.get('token_expires_at')

        if access_token and expires_at:
            # Check if token has expired
            if time.time() > expires_at:
                try:
                    auth_manager = get_spotify_auth_manager(request)
                    token_info = auth_manager.refresh_access_token(
                        request.session['refresh_token'])
                    access_token = token_info['access_token']
                    request.session['access_token'] = access_token
                    request.session['token_expires_at'] = token_info[
                        'expires_at']
                    request.session.modified = True
                except Exception as e:
                    logger.error(f"Error refreshing Spotify token: {str(e)}")
                    return redirect('login')

            try:
                spotify = spotipy.Spotify(auth=access_token)
                spotify.me()  # Verify token is valid
                return view_func(request, *args, **kwargs)
            except Exception as e:
                logger.warning(f"Spotify token validation failed: {str(e)}")
                # Clear only Spotify-related session data
                spotify_keys = ['spotify_auth_cache', 'spotify_id',
                                'access_token', 'spotify_auth_state']
                for key in spotify_keys:
                    request.session.pop(key, None)
                request.session.modified = True
                return redirect('login')

        # If no token or invalid state, store next URL and redirect to login
        request.session['next'] = request.get_full_path()
        return redirect('login')

    return wrapper

    return render(request, 'wrapped/addFriends.html', {
        'user_name': user_name,
        'profile_image': profile_image,
        'spotify_id': spotify_id,
        'friends': friends,
        'has_friends': friends.exists()
    })
"""

import time

def require_spotify_auth(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        access_token = request.session.get('access_token')
        expires_at = request.session.get('token_expires_at')

        if access_token and expires_at:
            # Check if token has expired
            if time.time() > expires_at:
                try:
                    auth_manager = get_spotify_auth_manager(request)
                    token_info = auth_manager.refresh_access_token(request.session['refresh_token'])
                    access_token = token_info['access_token']
                    request.session['access_token'] = access_token
                    request.session['token_expires_at'] = token_info['expires_at']
                    request.session.modified = True
                except Exception as e:
                    logger.error(f"Error refreshing Spotify token: {str(e)}")
                    return redirect('login')

            try:
                spotify = spotipy.Spotify(auth=access_token)
                spotify.me()  # Verify token is valid
                return view_func(request, *args, **kwargs)
            except Exception as e:
                logger.warning(f"Spotify token validation failed: {str(e)}")
                # Clear only Spotify-related session data instead of flushing everything
                spotify_keys = ['spotify_auth_cache', 'spotify_id', 'access_token', 'spotify_auth_state']
                for key in spotify_keys:
                    request.session.pop(key, None)
                request.session.modified = True
                return redirect('login')

        # If no token or invalid state, store next URL and redirect to login
        request.session['next'] = request.get_full_path()
        return redirect('login')

    return wrapper


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
    query = request.GET.get('query', '').strip()

    if not query:
        return JsonResponse({
            'success': False,
            'error': 'Please provide a search query'
        })

    try:
        users = SpotifyUser.objects.filter(
            wrapped_id__icontains=query
        ).exclude(
            spotify_id=request.session.get('spotify_id')
        )[:5]

        results = [{
            'spotify_id': user.spotify_id,
            'user_name': user.user_name,
            'profile_image': user.profile_image,
            'wrapped_id': user.wrapped_id
        } for user in users]

        return JsonResponse({
            'success': True,
            'results': results
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        })

    
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

        profile_image = None
        if user_profile.get('images') and len(user_profile['images']) > 0:
            profile_image = user_profile['images'][0]['url']

        current_user = SpotifyUser.objects.get(spotify_id=spotify_id)
        wrapped_id = current_user.wrapped_id
        friends = current_user.friends.all()

        return render(request, 'wrapped/addFriends.html', {
            'user_name': user_name,
            'profile_image': profile_image,
            'spotify_id': spotify_id,
            'friends': friends,
            'has_friends': friends.exists(),
            'wrapped_id': wrapped_id
        })

    except SpotifyUser.DoesNotExist:
        logger.error(f"User not found in database")
        return redirect('login')
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

    top_tracks = spotify.current_user_top_tracks(
        limit=50,
        offset=0,
        time_range=spotify_time_range,
    )
    
    tracks_data = []
    artists_data = []
    genre_count = {}

    if holiday_theme != 'none':
        # Map the frontend holiday theme names
        holiday_map = {
            'birthday': 'birthday',
            'valentines': 'valentines'
        }
        mapped_holiday = holiday_map.get(holiday_theme)
        holiday_criteria = get_holiday_keywords(mapped_holiday) if mapped_holiday else {}
        
        matched_artists_dict = {}
        genre_count = {}
        
        for track in top_tracks['items']:
            artist_id = track['artists'][0]['id']
            artist = spotify.artist(artist_id)
            
            # Now using holiday_criteria that we defined above
            if is_holiday_match(track, artist, None, holiday_criteria):
                track_data = {
                    'name': track['name'],
                    'artist': artist['name'],
                    'image_url': track['album']['images'][0]['url'] if track['album']['images'] else None,
                    'preview_url': track['preview_url']
                }
                tracks_data.append(track_data)
                
                if artist_id not in matched_artists_dict:
                    matched_artists_dict[artist_id] = {
                        'name': artist['name'],
                        'image_url': artist['images'][0]['url'] if artist['images'] else None,
                        'genres': artist['genres']
                    }
                    for genre in artist['genres']:
                        genre_count[genre] = genre_count.get(genre, 0) + 1
            
                if len(tracks_data) >= 10:
                    break
        
        artists_data = list(matched_artists_dict.values())

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

        top_artists = spotify.current_user_top_artists(
            limit=10,  
            offset=0,
            time_range=spotify_time_range
        )
        
        genre_count = {}  
        artists_data = []
        
        for artist in top_artists['items']:
            artists_data.append({
                'name': artist['name'],
                'image_url': artist['images'][0]['url'] if artist['images'] else None,
                'genres': artist['genres']
            })
            for genre in artist['genres']:
                genre_count[genre] = genre_count.get(genre, 0) + 1
            
            if len(artists_data) >= 10:
                break

    top_genres = sorted(genre_count.items(), key=lambda x: x[1], reverse=True)[:5]
    formatted_genres = [
        {
            'name': ' '.join(word.capitalize() for word in genre.replace('-', ' ').split()),
            'count': count
        } for genre, count in top_genres
    ]

    wrap = SavedWrap.objects.create(
        user=spotify_user,
        title=request.session.get('wrapped_name', 'My Wrap'),
        tracks_data=tracks_data,
        artists_data=artists_data,
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
        
        wraps = SavedWrap.objects.filter(user=spotify_user).order_by('-created_at')
        
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
    
def duo_comparison(request, friend_id):
    try:
        friend = SpotifyUser.objects.get(spotify_id=friend_id)
        
        friend_wrap = SavedWrap.objects.filter(user=friend).order_by('-created_at').first()
        
        friend_songs = []
        if friend_wrap:
            if isinstance(friend_wrap.tracks_data, dict) and 'current_user_tracks' in friend_wrap.tracks_data:
                friend_songs = friend_wrap.tracks_data['current_user_tracks'][:5]
            elif isinstance(friend_wrap.tracks_data, list):
                friend_songs = friend_wrap.tracks_data[:5]
        
        current_user_songs = []
        spotify_id = request.session.get('spotify_id')
        if spotify_id:
            try:
                current_user = SpotifyUser.objects.get(spotify_id=spotify_id)
                current_user_wrap = SavedWrap.objects.filter(user=current_user).order_by('-created_at').first()
                if current_user_wrap:
                    if isinstance(current_user_wrap.tracks_data, dict) and 'current_user_tracks' in current_user_wrap.tracks_data:
                        current_user_songs = current_user_wrap.tracks_data['current_user_tracks'][:5]
                    elif isinstance(current_user_wrap.tracks_data, list):
                        current_user_songs = current_user_wrap.tracks_data[:5]
            except SpotifyUser.DoesNotExist:
                pass
        
        friend_has_wrap = bool(friend_wrap and friend_songs)
        
        if friend_has_wrap:
            duo_wrap = SavedWrap(
                user=current_user,
                title=f"Duo Wrapped - {friend.user_name}",
                tracks_data={
                    'current_user_tracks': current_user_songs,
                    'friend_tracks': friend_songs
                },
                friend_tracks_data=friend_songs,
                artists_data=[],
                genres_data=[],
                created_at=timezone.now(),
                time_range='all_time'
            )
            duo_wrap.save()
        
        context = {
            'friend': friend,
            'friend_has_wrap': friend_has_wrap,
            'friend_songs': friend_songs,
            'current_user_songs': current_user_songs,
        }
        
        return render(request, 'wrapped/duo_comparison.html', context)
        
    except SpotifyUser.DoesNotExist:
        messages.error(request, 'User not found.')
        return redirect('home')
    
@require_spotify_auth
def get_wrap_share(request, wrap_id):
    try:
        wrap = get_object_or_404(SavedWrap, id=wrap_id)

        if wrap.user.spotify_id != request.session.get('spotify_id'):
            return JsonResponse({
                'success': False,
                'error': 'Unauthorized access'
            })

        top_genres = [genre['name'] if isinstance(genre, dict) else genre
                      for genre in wrap.genres_data[:3]]

        share_data = {
            'title': wrap.title,
            'top_tracks': [track['name'] for track in wrap.tracks_data[:5]],
            'top_artists': [artist['name'] for artist in wrap.artists_data[:5]],
            'top_genres': top_genres,
            'time_range': wrap.time_range,
            'wrapped_id': wrap.user.wrapped_id
        }

        return JsonResponse({
            'success': True,
            'wrap': share_data
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        })
    
def get_holiday_keywords(holiday):
    holiday_criteria = {
        'birthday': {  
            'keywords': [
                'party', 'celebrate', 'celebration', 'dance', 'birthday', 'happy', 
                'fun', 'tonight', 'club', 'groove', 'move', 'rhythm', 'beat', 'joy',
                'weekend', 'night', 'dancing', 'party', 'wild', 'crazy', 'jump',
                'hands up', 'disco', 'bass', 'bounce', 'energy', 'fire', 'lit',
                'festival', 'rave', 'party time', 'good time', 'lets go', 'pump',
                'rock', 'bang', 'boom', 'drop', 'vibe', 'feeling', 'alive'
            ],
            'genres': [
                'dance', 'pop', 'disco', 'party', 'electronic', 'funk', 'hip-hop', 
                'dance pop', 'edm', 'house', 'club', 'trap', 'urban',
                'electro house', 'pop dance', 'pop rap', 'tropical house',
                'uk dance', 'deep house', 'bass house', 'big room',
                'pop edm', 'future house', 'groove', 'tech house',
                'dance rock', 'electro pop', 'disco house', 'party rap',
                'pop house', 'progressive house', 'slap house'
            ],
            'audio_features': {
                'valence': 0.6,
                'energy': 0.65,
                'tempo': (100, 200)
            }
        },
    'valentines': {
        'keywords': ['love', 'heart', 'romance', 'valentine', 'kiss', 'date', 'forever', 'darling', 
                    'sweetheart', 'romantic', 'passion', 'embrace', 'baby', 'honey', 'dear',
                    'beautiful', 'sweet', 'angel', 'dream', 'lover', 'soul', 'eyes',
                    'touch', 'hold', 'dance', 'moonlight', 'stars', 'night', 'slow',
                    'close', 'soft', 'gentle', 'tender', 'feelings', 'emotion',
                    'together', 'always', 'yours', 'mine', 'us', 'two', 'couple',
                    'perfect', 'special', 'moment', 'endless', 'eternal', 'destiny'],
        'genres': ['romance', 'singer-songwriter', 'pop'],
            'audio_features': {
                'valence': 0.6,  
                'energy': 0.4,   
                'tempo': (60, 120)
            }
    }
    }
    return holiday_criteria.get(holiday, {})

def is_holiday_match(track, artist, audio_features, criteria):
    if not criteria:
        return False
        
    # Check for keyword matches in track name, artist name, and album name
    track_name_lower = track['name'].lower()
    artist_name_lower = artist['name'].lower()
    album_name_lower = track['album']['name'].lower()
    keywords = criteria.get('keywords', [])
    
    # If it's a keyword match anywhere, include it automatically
    if (any(keyword in track_name_lower for keyword in keywords) or
        any(keyword in artist_name_lower for keyword in keywords) or
        any(keyword in album_name_lower for keyword in keywords)):
        return True
    
    # If no keyword match, check genres
    genres = criteria.get('genres', [])
    artist_genres = artist['genres']
    
    # Return True if any genre matches (removed audio features check)
    return any(genre in artist_genres for genre in genres)