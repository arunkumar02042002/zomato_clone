# Django Imports
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.contrib.auth.hashers import check_password
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode 
from django.contrib.auth.tokens import default_token_generator


# Rest Import
from rest_framework import status
from rest_framework.test import APIClient

# SimpleJWT Imports
from rest_framework_simplejwt.tokens import RefreshToken

# Local Imports
from .tokens import account_activation_token
from .helpers import AuthHelper


User = get_user_model()


class UserModelTest(TestCase):

    def setUp(self) -> None:
        self.user = User.objects.create_user(
            email='test@gmail.com',
            username='test_user',
            first_name='Test',
            last_name='User',
            password='testpassword'
        )
        self.superuser = User.objects.create_superuser(
            email='admin@gmail.com',
            username='admin123',
            first_name='Admin',
            last_name='User',
            password='testpassword'
        )

    def test_create_user(self):
        
        self.assertEqual(self.user.email, 'test@gmail.com')
        self.assertEqual(self.user.username, 'test_user')
        self.assertEqual(self.user.first_name, 'Test')
        self.assertEqual(self.user.last_name, 'User')
        self.assertTrue(self.user.check_password('testpassword'))
        self.assertEqual(self.user.user_type, 'USER')
        self.assertFalse(self.user.is_staff)
        self.assertTrue(self.user.is_active)
        self.assertFalse(self.user.is_superuser)

    def test_create_superuser(self):

        self.assertEqual(self.superuser.email, 'admin@gmail.com')
        self.assertEqual(self.superuser.username, 'admin123')
        self.assertEqual(self.superuser.first_name, 'Admin')
        self.assertEqual(self.superuser.last_name, 'User')
        self.assertTrue(self.superuser.check_password('testpassword'))
        self.assertEqual(self.superuser.user_type, 'ADMIN')
        self.assertTrue(self.superuser.is_staff)
        self.assertTrue(self.superuser.is_active)
        self.assertTrue(self.superuser.is_superuser)


class SignUpViewTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.signup_url = reverse('register-user')

    def test_signup_success(self):
        """
        Test successful user signup.
        """
        data = {
            'email': 'test@example.com',
            'password': 'test_password',
        }

        response = self.client.post(self.signup_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(User.objects.count(), 1)

        user = User.objects.first()

        self.assertEqual(user.user_type, 'USER')
        self.assertFalse(user.is_active)
        self.assertEqual(user.email, 'test@example.com')
        self.assertTrue(check_password(password='test_password', encoded=user.password))

    def test_signup_existing_user(self):
        """
        Test signup with an existing user email.
        """
        existing_user = User.objects.create_user(email='existing@example.com', username='existing_user', password='existing_password')
        data = {
            'email': 'existing@example.com',
            'password': 'test_password',
        }
        response = self.client.post(self.signup_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(User.objects.count(), 1)  # No new user should be created

    def test_signup_email_validation_errors(self):
        """
        Test signup with invalid data.
        """
        data = {
            'email': 'test.com',
            'password': 'test_password'
        }
        response = self.client.post(self.signup_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_signup_password_validation_errors(self):
        """
        Test signup with invalid data.
        """
        data = {
            'email': 'test@gmail.com',
            'password': ''
        }
        response = self.client.post(self.signup_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class ActivateAccountViewTest(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_activation_success(self):
        """
        Test activation with valid token and UID.
        """
        user = User.objects.create_user(email='test@example.com', username='test_user', password='test_password', is_active=False)
        uidb64 = urlsafe_base64_encode(force_bytes(user.id))
        token = account_activation_token.make_token(user)
        
        response = self.client.get(reverse('activate-account', kwargs={'uidb64': uidb64, 'token': token}))
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(User.objects.get(id=user.id).is_active)

    def test_activation_invalid_link(self):
        """
        Test activation with invalid token or UID.
        """
        # Make a GET request to the activation URL with invalid token and UID
        response = self.client.get(reverse('activate-account', kwargs={'uidb64': 'inavlid_uidb64', 'token': 'invalid_token'}))

        # Check if the response indicates an error due to invalid activation link
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class LoginViewTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.login_url = reverse('login')
        # Create a user for testing
        self.user = User.objects.create_user(username='testuser', email='test@example.com',  password='test_password', is_active=True)

    def test_login_success_using_username(self):
        """
        Test successful login.
        """
        data = {
            'username_or_email': 'testuser',
            'password': 'test_password',
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data['payload'])

    def test_login_success_using_email(self):
        """
        Test successful login.
        """
        data = {
            'username_or_email': 'test@example.com',
            'password': 'test_password',
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data['payload'])

    def test_login_invalid_credentials(self):
        """
        Test login with invalid credentials.
        """
        data = {
            'username_or_email': 'testuser',
            'password': 'wrong_password',
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_inactive_user(self):
        """
        Test login with inactive user.
        """
        # Deactivate the user
        self.user.is_active = False
        self.user.save()
        data = {
            'username_or_email': 'testuser',
            'password': 'test_password',
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_login_no_user_found(self):
        """
        Test login with non-existent user.
        """
        data = {
            'username_or_email': 'nonexistentuser',
            'password': 'test_password',
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class UserLogoutViewTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.logout_url = reverse('logout')
        # Create a user for testing
        self.user = User.objects.create_user(username='testuser', email='test@example.com', password='test_password', is_active=True)
        self.refresh = str(RefreshToken.for_user(user=self.user))
        

    def test_logout_success(self):
        """
        Test successful logout.
        """
        
        data = {'refresh': self.refresh}
        self.client.force_authenticate(self.user)

        response = self.client.post(self.logout_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_logout_all_devices(self):
        """
        Test logout from all devices.
        """
        data = {'all': True}
        self.client.force_authenticate(self.user)
        self.refresh_token = RefreshToken.for_user(self.user)

        response = self.client.post(self.logout_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_logout_invalid_token(self):
        """
        Test logout with invalid refresh token.
        """
        data = {'refresh': 'invalid_refresh_token'}
        self.client.force_authenticate(self.user)
        response = self.client.post(self.logout_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_logout_unauthenticated(self):
        """
        Test logout when user is not authenticated.
        """
        data = {'refresh': self.refresh}
        response = self.client.post(self.logout_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class CustomTokenRefreshViewTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.refresh_url = reverse('get-refresh-token')
        # Create a user for testing
        self.user = User.objects.create_user(username='testuser', email='test@example.com', password='test_password', is_active=True)
        # Create a refresh token for testing
        self.refresh_token = str(RefreshToken.for_user(self.user))

    def test_refresh_token_success(self):
        """
        Test successful token refresh.
        """
        data = {'refresh': self.refresh_token}
        response = self.client.post(self.refresh_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_refresh_inactive_user(self):
        """
        Test token refresh with inactive user.
        """
        # Deactivate the user
        self.user.is_active = False
        self.user.save()
        data = {'refresh': self.refresh_token}
        response = self.client.post(self.refresh_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class ChangePasswordViewTest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.change_password_url = reverse('change-password')
        # Create a user for testing
        self.user = User.objects.create_user(username='testuser', email='test@example.com', password='test_password')

    def test_change_password_success(self):
        """
        Test successful password change.
        """
        data = {
            'old_password': 'test_password',
            'new_password': 'new_test_password',
            'confirm_password': 'new_test_password',
        }
        self.client.force_authenticate(user=self.user)
        response = self.client.post(self.change_password_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_change_password_incorrect_old_password(self):
        """
        Test changing password with incorrect old password.
        """
        data = {
            'old_password': 'incorrect_password',
            'new_password': 'new_test_password',
            'confirm_password': 'new_test_password',
        }
        self.client.force_authenticate(user=self.user)
        response = self.client.post(self.change_password_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_change_password_incorrect_confirm_password(self):
        """
        Test changing password with incorrect confirm password.
        """
        data = {
            'old_password': 'incorrect_password',
            'new_password': 'new_test_password',
            'confirm_password': 'new_test_password2',
        }
        self.client.force_authenticate(user=self.user)
        response = self.client.post(self.change_password_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class PasswordResetViewTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.password_reset_url = reverse('password-reset')
        # Create a user for testing
        self.user = User.objects.create_user(username='testuser', email='test@example.com', password='test_password')

    def test_password_reset_success(self):
        """
        Test successful password reset.
        """
        data = {'email': 'test@example.com'}
        response = self.client.post(self.password_reset_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        

    def test_password_reset_non_existent_email(self):
        """
        Test password reset with non-existent email.
        """
        data = {'email': 'nonexistent@example.com'}
        response = self.client.post(self.password_reset_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_reset_for_inactive_user(self):
        """
        Test password reset with non-existent email.
        """
        self.user.is_active = False
        self.user.save()
        data = {'email': 'test@example.com'}
        response = self.client.post(self.password_reset_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirmViewTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(username='testuser', email='test@example.com', password='test_password')
        self.reset_confirm_url = reverse('password-reset-confirm', kwargs={'uidb64': urlsafe_base64_encode(force_bytes(self.user.pk)), 'token': default_token_generator.make_token(self.user)})
        
    def test_password_reset_confirm_success(self):
        """
        Test successful password reset confirmation.
        """
        data = {'new_password': 'new_test_password', 'confirm_password':'new_test_password'}
        response = self.client.post(self.reset_confirm_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_password_reset_confirm_incorrect_confirm_password(self):
        """
        Test incorrect confirm_password field.
        """
        data = {'new_password': 'new_test_password', 'confirm_password':'incorrect_test_password'}
        response = self.client.post(self.reset_confirm_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_reset_confirm_invalid_token(self):
        """
        Test password reset confirmation with invalid token.
        """
        # Generate an invalid token by modifying the user's token
        invalid_token = default_token_generator.make_token(User())
        invalid_reset_confirm_url = reverse('password-reset-confirm', kwargs={'uidb64': urlsafe_base64_encode(force_bytes(self.user.pk)), 'token': invalid_token})
        data = {'new_password': 'new_test_password', 'confirm_password':'new_test_password'}
        response = self.client.post(invalid_reset_confirm_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
