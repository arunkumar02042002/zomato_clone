
from django.test import TestCase
from django.db.models.signals import post_save
from django.contrib.auth import get_user_model


from authentication.signals import post_save_create_profile_receiver

from .models import Profile, Restaurant, OpeningHour


User = get_user_model()


class RestaurantModelTest(TestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Disconnect the post_save signal to avoid creating Profile objects automatically
        post_save.disconnect(receiver=post_save_create_profile_receiver, sender=User)

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        # Reconnect the post_save signal after testing
        post_save.connect(receiver=post_save_create_profile_receiver, sender=User)

    def setUp(self):
        # Create a user and profile for testing
        self.user = User.objects.create_user(username='testuser', email='test@example.com', password='test_password')
        self.profile = Profile.objects.create(user=self.user)
        self.restaurant = Restaurant.objects.create(
            user=self.user,
            profile=self.profile,
            name='Test Restaurant',
            slug='test-restaurant',
            license='license.jpg',
            is_approved=True
        )

    def test_restaurant_creation(self):
        """
        Test restaurant creation.
        """
        self.assertEqual(self.restaurant.name, 'Test Restaurant')
        self.assertEqual(self.restaurant.slug, 'test-restaurant')
        self.assertEqual(self.restaurant.is_approved, True)

    def test_unique_name_constraint(self):
        """
        Test unique name constraint.
        """
        # Attempt to create another restaurant with the same name
        with self.assertRaises(Exception):
            Restaurant.objects.create(
                user=self.user,
                profile=self.profile,
                name='Test Restaurant',  # Attempt to create with the same name
                slug='test-restaurant-2',
                license='license.jpg',
                is_approved=True
            )

    def test_relationships(self):
        """
        Test relationships with User and Profile models.
        """
        self.assertEqual(self.restaurant.user, self.user)
        self.assertEqual(self.restaurant.profile, self.profile)


class OpeningHourModelTest(TestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Disconnect the post_save signal to avoid creating Profile objects automatically
        post_save.disconnect(receiver=post_save_create_profile_receiver, sender=User)

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        # Reconnect the post_save signal after testing
        post_save.connect(receiver=post_save_create_profile_receiver, sender=User)

    def setUp(self):
        # Create a user and profile for testing
        self.user = User.objects.create_user(username='testuser', email='test@example.com', password='test_password')
        self.profile = Profile.objects.create(user=self.user)
        # Create a restaurant for testing
        self.restaurant = Restaurant.objects.create(user=self.user, profile=self.profile, name='Test Restaurant', slug='test-restaurant')
        self.opening_hour = OpeningHour.objects.create(
            Restaurants=self.restaurant,
            day=1,
            from_hour='08:00 AM',
            to_hour='05:00 PM',
            is_closed=False
        )

    def test_opening_hour_creation(self):
        """
        Test opening hour creation.
        """
        
        self.assertEqual(self.opening_hour.day, 1)
        self.assertEqual(self.opening_hour.from_hour, '08:00 AM')
        self.assertEqual(self.opening_hour.to_hour, '05:00 PM')
        self.assertEqual(self.opening_hour.is_closed, False)

    def test_unique_together_constraint(self):
        """
        Test unique together constraint.
        """
        # Attempt to create another opening hour with the same attributes
        with self.assertRaises(Exception):
            OpeningHour.objects.create(
                Restaurants=self.restaurant,
                day=1,
                from_hour='08:00 AM',
                to_hour='05:00 PM',
                is_closed=False
            )

    def test_relationship_with_restaurant(self):
        """
        Test relationship with the Restaurant model.
        """
        self.assertEqual(self.opening_hour.Restaurants, self.restaurant)
