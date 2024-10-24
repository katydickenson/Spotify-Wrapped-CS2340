import logging
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.conf import settings
import spotipy
from spotipy.oauth2 import SpotifyOAuth
from functools import wraps

logger = logging.getLogger(__name__)


def require_spotify_auth(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        access_token = request.session.get('access_token')

        if not access_token:
            # Store the intended destination URL in the session
            request.session['next'] = request.get_full_path()
            return redirect('login')

        try:
            # Verify the token is still valid
            spotify = spotipy.Spotify(auth=access_token)
            spotify.me()  # This will raise an exception if the token is invalid
            return view_func(request, *args, **kwargs)
        except Exception as e:
            logger.warning(f"Spotify token validation failed: {str(e)}")
            request.session.flush()
            return redirect('login')

    return wrapper


def get_spotify_auth_manager(request):
    scope = 'user-read-private user-read-email'
    cache_handler = None  # Don't use cache handler to prevent auto-login

    return SpotifyOAuth(
        client_id=settings.SPOTIFY_CLIENT_ID,
        client_secret=settings.SPOTIFY_CLIENT_SECRET,
        redirect_uri=settings.SPOTIFY_REDIRECT_URI,
        scope=scope,
        cache_handler=cache_handler,
        show_dialog=True  # Always show the Spotify login dialog
    )


@require_spotify_auth
def home(request):
    spotify = spotipy.Spotify(auth=request.session['access_token'])
    user_name = spotify.me().get('display_name', 'User')

    return render(request, 'wrapped/home.html', {
        'user_name': user_name
    })


def login(request):
    """Show the custom login page"""
    return render(request, 'wrapped/login.html')


def initiate_spotify_auth(request):
    """Handle the actual Spotify authentication after user clicks the button"""
    # Clear any existing session data
    request.session.flush()

    # Ensure session is created
    if not request.session.session_key:
        request.session.create()

    auth_manager = get_spotify_auth_manager(request)
    auth_url = auth_manager.get_authorize_url()

    return redirect(auth_url)


def spotify_callback(request):
    error = request.GET.get('error')
    if error:
        logger.error(f"Spotify authentication error: {error}")
        return redirect('login')

    code = request.GET.get('code')
    if not code:
        logger.error("No authorization code received from Spotify")
        return redirect('login')

    try:
        auth_manager = get_spotify_auth_manager(request)
        token_info = auth_manager.get_access_token(code)
        access_token = token_info.get('access_token')

        if not access_token:
            raise ValueError("No access token returned")

        # Store the access token in the session
        request.session['access_token'] = access_token
        request.session.modified = True

        # Redirect to the stored 'next' URL or home
        next_url = request.session.pop('next', 'home')
        return redirect(next_url)

    except Exception as e:
        logger.error(f"Error during Spotify callback: {str(e)}")
        return redirect('login')


def logout(request):
    request.session.flush()
    return redirect('login')