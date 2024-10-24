from urllib.parse import urlencode
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.conf import settings
import base64
import hashlib
import os
import requests
import logging
from .models import SpotifyUser

logger = logging.getLogger(__name__)


def home(request):
    user_name = request.session.get('user_name')
    access_token = request.session.get('access_token')

    if access_token is None:
        return redirect('login')  # Redirect to login if not authenticated

    return render(request, 'wrapped/home.html', {'user_name': user_name})


def login(request):
    return render(request, 'wrapped/login.html')


def generate_code_verifier():
    token = os.urandom(96)
    code_verifier = base64.urlsafe_b64encode(token).decode('utf-8')
    return code_verifier.replace('=', '')


def generate_code_challenge(code_verifier):
    sha256_hashed = hashlib.sha256(code_verifier.encode()).digest()
    base64_encoded = base64.urlsafe_b64encode(sha256_hashed).decode('utf-8')
    # Step 3: Remove any padding (=)
    code_challenge = base64_encoded.replace('=', '')
    return code_challenge


def spotify_login(request):
    # Clear specific session keys instead of flushing entire session
    request.session.pop('code_verifier', None)

    code_verifier = generate_code_verifier()

    # Store code verifier in session
    request.session['code_verifier'] = code_verifier
    request.session.modified = True

    logger.debug(f"Code verifier set: {code_verifier}")

    code_challenge = generate_code_challenge(code_verifier)
    logger.debug(f"Code challenge: {code_challenge}")

    auth_url = "https://accounts.spotify.com/authorize"
    auth_params = {
        "client_id": settings.SPOTIFY_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": settings.SPOTIFY_REDIRECT_URI,
        "code_challenge_method": "S256",
        "code_challenge": code_challenge,
        "scope": "user-read-private user-read-email"
    }

    auth_request_url = f"{auth_url}?{urlencode(auth_params)}"
    logger.debug(f"Auth URL: {auth_request_url}")

    return redirect(auth_request_url)


def spotify_callback(request):
    code = request.GET.get('code')
    if not code:
        logger.error("No authorization code received")
        return HttpResponse("No authorization code received", status=400)

    code_verifier = request.session.get('code_verifier')
    if not code_verifier:
        logger.error("No code verifier found in session")
        return HttpResponse("No code verifier found in session", status=400)

    logger.debug(f"Retrieved code: {code}")
    logger.debug(f"Retrieved code_verifier: {code_verifier}")

    token_url = "https://accounts.spotify.com/api/token"
    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.SPOTIFY_REDIRECT_URI,
        "client_id": settings.SPOTIFY_CLIENT_ID,
        "code_verifier": code_verifier
    }

    logger.debug(f"Token request data: {token_data}")

    try:
        response = requests.post(token_url, data=token_data)
        if response.status_code != 200:
            logger.error(
                f"Token exchange failed. Status: {response.status_code}")
            logger.error(f"Response: {response.text}")
            return HttpResponse(f"Token exchange failed: {response.text}",
                                status=400)

        token_info = response.json()

        request.session['access_token'] = token_info['access_token']

        headers = {"Authorization": f"Bearer {token_info['access_token']}"}
        user_response = requests.get("https://api.spotify.com/v1/me",
                                     headers=headers)
        user_data = user_response.json()

        request.session['user_name'] = user_data.get('display_name', 'Guest')
        request.session['user_id'] = user_data['id']

        request.session.pop('code_verifier', None)
        request.session.modified = True

        return redirect('home')

    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed: {str(e)}")
        return HttpResponse(f"Error: {str(e)}", status=400)