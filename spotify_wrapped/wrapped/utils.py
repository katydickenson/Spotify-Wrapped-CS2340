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
model = genai.GenerativeModel('gemini-pro')


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
        try:
            prompt = f"""
                        Based on these music preferences over:
                        Top Genres: {genres}
                        Top Artists: {artists}

                        Create a personality description of this music listener. 
                        Format the response as a string with these sections:
                        - Overall Vibe
                        - Personality Traits (number or put dashes in front of the list)
                        - Music Recommendations (number or put dashes in front of the list) (limit to 5)

                        Keep each section short and engaging.
                        """
            response = model.generate_content(prompt).text

            logger.info(f"Successfully generated personality description for genres: {genres}")

            split_personality = response.split('\n\n')

            num = 0
            for cur in split_personality:
                split_personality[num] = cur.replace("*", "")
                num += 1
            just_text = []
            if num == 6:
                just_text.append(split_personality[1])
                just_text.append(split_personality[3].split('\n'))
                just_text.append(split_personality[5].split('\n'))
            elif num == 4:
                temp = split_personality[0].split('\n')
                temp_txt = []
                for line in temp:
                    if line != temp[0]:
                        temp_txt.append(line)
                temp_txt = '\n'.join(temp_txt)
                just_text.append(temp_txt)

                temp = split_personality[1].split('\n')
                temp_txt = []
                for line in temp:
                    if line != temp[0]:
                        temp_txt.append(line)
                temp_txt = '\n'.join(temp_txt)
                just_text.append(temp_txt.split('\n'))

                temp = split_personality[3].split('\n')
                temp_txt = []
                for line in temp:
                    if line != temp[0]:
                        temp_txt.append(line)
                temp_txt = '\n'.join(temp_txt)
                just_text.append(temp_txt.split('\n'))

            elif num == 3:
                if ': ' in split_personality[0]:
                    temp_txt = split_personality[0].split(':')
                    just_text.append(temp_txt[1])
                elif ':\n' in split_personality[0]:
                    temp_txt = split_personality[0].split(':\n')
                    just_text.append(temp_txt[1])
                elif 'e\n' in split_personality[0]:
                    temp_txt = split_personality[0].split('e\n')
                    just_text.append(temp_txt[1])
                else:
                    raise Exception("bad format")

                temp = split_personality[1].split('\n')
                temp_txt = []
                for line in temp:
                    if line != temp[0]:
                        temp_txt.append(line)
                temp_txt = '\n'.join(temp_txt)
                just_text.append(temp_txt.split('\n'))

                temp = split_personality[2].split('\n')
                temp_txt = []
                for line in temp:
                    if line != temp[0]:
                        temp_txt.append(line)
                temp_txt = '\n'.join(temp_txt)
                just_text.append(temp_txt.split('\n'))

            else:
                raise Exception("bad format")

            return just_text

        except Exception as e:
            logger.error(f"Error generating personality description: {str(e)}")
            raise

    @retry_on_failure(max_attempts=3)
    def friend_comparison(self, cur_user_songs, friend_songs):
        try:
            prompt = f"""
                                Based on the user's top songs and their friend's top songs:
                                User Songs: {cur_user_songs}
                                Friend Songs: {friend_songs}

                                Create a music and personality comparison for both users and songs that they both would like.
                                Refer to the User as 'you' and the friend as 'they'.
                                Format the response as a string with these sections:
                                - Music Comparison
                                - Personality Comparison
                                - Music Recommendations
                                
                                Music Recommendations should be formatted like this:
                                Based on your shared musical tastes, you and your friend might enjoy these songs:
                                and give 5 shared songs
                                
                                Keep each section short and engaging.
                                """
            response = model.generate_content(prompt)
            cut_response = response.text

            logger.info(f"Successfully generated personality description for current user songs: {cur_user_songs}")
            logger.info(f"Successfully generated personality description for current friend songs: {friend_songs}")

            split_comparison = cut_response.split('\n\n')

            num = 0
            for cur in split_comparison:
                split_comparison[num] = cur.replace("*", "")
                num += 1
            just_text = []
            if num == 7:
                just_text.append(split_comparison[1])
                just_text.append(split_comparison[3].split('\n'))
                just_text.append(split_comparison[6].split('\n'))
            elif num  == 6:
                just_text.append(split_comparison[1])
                just_text.append(split_comparison[3].split('\n'))
                if ': ' in split_comparison[5]:
                    temp_txt = split_comparison[5].split(': ')
                    just_text.append(temp_txt[1].split('\n'))
                elif ':\n' in split_comparison[5]:
                    temp_txt = split_comparison[5].split(':\n')
                    just_text.append(temp_txt[1].split('\n'))
                else:
                    raise Exception("bad format")
            elif num == 4:
                if ': ' in split_comparison[0]:
                    temp_txt = split_comparison[0].split(': ')
                    just_text.append(temp_txt[1])
                elif '\n' in split_comparison[0]:
                    temp_txt = split_comparison[0].split('\n')
                    just_text.append(temp_txt[1])
                else:
                    raise Exception("bad format")

                if ': ' in split_comparison[1]:
                    temp_txt = split_comparison[1].split(': ')
                    just_text.append(temp_txt[1].split('\n'))
                elif '\n' in split_comparison[1]:
                    temp_txt = split_comparison[1].split('\n')
                    just_text.append(temp_txt[1].split('\n'))
                else:
                    raise Exception("bad format")
                just_text.append(split_comparison[3].split('\n'))

            elif num == 3:
                if ': ' in split_comparison[0]:
                    temp_txt = split_comparison[0].split(': ')
                    just_text.append(temp_txt[1])
                elif ':\n' in split_comparison[0]:
                    temp_txt = split_comparison[0].split(':\n')
                    just_text.append(temp_txt[1])
                else:
                    raise Exception("bad format")

                if ': ' in split_comparison[1]:
                    temp_txt = split_comparison[1].split(': ')
                    just_text.append(temp_txt[1].split('\n'))
                elif ':\n' in split_comparison[1]:
                    temp_txt = split_comparison[1].split(':\n')
                    just_text.append(temp_txt[1].split('\n'))
                else:
                    raise Exception("bad format")

                if ': ' in split_comparison[2]:
                    temp_txt = split_comparison[2].split(': ')
                    just_text.append(temp_txt[1].split('\n'))
                elif ':\n' in split_comparison[2]:
                    temp_txt = split_comparison[2].split(':\n')
                    if len(temp_txt) == 3:
                        just_text.append(temp_txt[2].split('\n'))
                    else:
                        just_text.append(temp_txt[1].split('\n'))
                else:
                    raise Exception("bad format")

            else:
                raise Exception("bad format")
            return just_text

        except Exception as e:
            logger.error(f"Error generating personality description: {str(e)}")
            raise