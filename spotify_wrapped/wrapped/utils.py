import google.generativeai as genai
from markdown2 import markdown
import logging
import re
from django.conf import settings
from functools import wraps
from time import sleep
import google.generativeai as genai
import os

logger = logging.getLogger(__name__)
genai.configure(api_key="GEMINI_API_KEY")


def retry_on_failure(max_attempts=3, delay=1):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            attempts = 0
            while attempts < max_attempts:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    attempts += 1
                    logger.error(f"Attempt {attempts} failed: {str(e)}")
                    if attempts == max_attempts:
                        raise
                    sleep(delay)
            return None
        return wrapper
    return decorator


class GeminiPersonalityGenerator:
    def __init__(self):
        self.api_key = settings.GEMINI_API_KEY
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel('gemini-pro')

    @retry_on_failure(max_attempts=3)
    def generate_personality_description(gem, genres, artists):
        #genai.configure(api_key='GEMINI_API_KEY')
        model = genai.GenerativeModel('gemini-pro')
        print("genres:")
        print(genres)
        print("artists:")
        print(artists)
        try:
            prompt = f"""
                        Based on these music preferences over:
                        Top Genres: {genres}
                        Top Artists: {artists}

                        Create a personality description of this music listener. 
                        Format the response as a string with these sections:
                        - Overall Vibe
                        - Personality Traits
                        - Music Recommendations

                        Keep each section short and engaging.
                        """
            response = model.generate_content(prompt)

            logger.info(f"Successfully generated personality description for genres: {genres}")
            return response.text

        except Exception as e:
            logger.error(f"Error generating personality description: {str(e)}")
            raise


    def markdown_to_html(markdown_text):
        try:
            return markdown(markdown_text)
        except Exception as e:
            logger.error(f"Error formatting markdown: {str(e)}")
            return f"<p>Error formatting response. Please try again.</p>"


