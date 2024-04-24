from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from .models import User, Profile


@receiver(post_save, sender=User)
def post_save_create_profile_receiver(sender, instance, created, **kwargs):

    if created:
        Profile.objects.create(user=instance)
    else:
        # Create Profile if not exists.
        Profile.objects.get_or_create(user=instance)
