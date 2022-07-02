from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token
import logging

logger = logging.getLogger("veach")

@receiver(post_save, sender=User)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        try:
            Token.objects.create(user=instance)
            logger.info(
                "[TOKEN CREATED FOR USER] User ID: " + str(instance.id))
        except:
            logger.error(
                "[FAILED TOKEN CREATION] User ID: " + str(instance.id), exc_info=True)