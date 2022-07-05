""" 
This settings file contains all the settings that should be applied to production. 
"""

import os
from .common import *
from django.core.management.utils import get_random_secret_key

# SECURITY WARNING: keep the secret key used in production secret!
# The SECRET_KEY will be read as an environment variable; if there isn't a enviroment variable
# it will be get a secret key from get_random_secret_key
SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", get_random_secret_key())

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.getenv("DEBUG", False)

ALLOWED_HOSTS = os.getenv("DJANGO_ALLOWED_HOSTS",
                          "127.0.0.1,localhost,0.0.0.0").split(",")

# Database
# https://docs.djangoproject.com/en/4.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'djongo',
        'NAME': 'veachdb',
        # 'CLIENT': {
        #     'host': 'mongodb+srv://veach:gfFVGjpGfeayd3Qe@cluster0.gnukl.mongodb.net/?retryWrites=true&w=majority',
        #     'name': 'mytestdb',
        #     'authMechanism': 'SCRAM-SHA-1'
        # }
    }
}

##### Security Settings #####
# CSRF_COOKIE_SECURE = True
# SESSION_COOKIE_SECURE = True
# SECURE_SSL_REDIRECT = True
