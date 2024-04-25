# Django Imports
from django.db import models
from django.contrib.auth import get_user_model

# Other imports
from datetime import time

# Other apps import
from authentication.models import Profile

User = get_user_model()

# Create your models here.
class Restaurant(models.Model):

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    profile = models.OneToOneField(Profile, on_delete=models.CASCADE)

    name = models.CharField(max_length=50, unique=True, db_index=True)
    slug = models.SlugField(max_length=100, unique=True, db_index=True)

    license = models.ImageField(upload_to='restaurants/license')
    is_approved = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.vendor_name


class DaysChoices:    
    days = {
        1:"MONDAY",
        2:"TUESDAY",
        3:"WEDNESDAY",
        4:"THURSDAY",
        5:"FRIDAY",
        6:"SATURDAY",
        7:"SUNDAY",
    }

    choices = list(days.items())

class HoursChoices:
    choices = [
        (time(h, m).strftime('%I:%M %p'), time(h, m).strftime('%I:%M %p')) 
        for h in range(0, 24)
        for m in (0, 30)
        ]

class OpeningHour(models.Model):

    Restaurants = models.ForeignKey(Restaurant, on_delete=models.CASCADE)

    day = models.IntegerField(choices=DaysChoices.choices)
    from_hour = models.CharField(choices=HoursChoices.choices, max_length=10, blank=True)
    to_hour = models.CharField(choices=HoursChoices.choices, max_length=10, blank=True)
    is_closed = models.BooleanField(default=False)

    class Meta:
        ordering = ('day', '-from_hour')
        unique_together = ('Restaurants', 'day', 'from_hour', 'to_hour')

    def __str__(self):
        return DaysChoices.day.get(self.day)+self.Restaurants.name