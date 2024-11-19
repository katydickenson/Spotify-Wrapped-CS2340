# wrapped/templatetags/text_filters.py
from django import template
register = template.Library()

@register.filter
def split(value, arg):
    return value.split(arg)