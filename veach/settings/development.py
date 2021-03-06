""" 
This settings file contains all the settings that should be applied to development. 
"""
from .common import *

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'ez%$_9r3z1&kg92buuqj8s%*mv=*z@8ny5g5w@7zvh(p1p606'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']


# Database
# https://docs.djangoagents_group.com/en/3.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'djongo',
        'NAME': 'veachdb',
    }
}
