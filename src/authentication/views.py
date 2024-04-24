# Django imports
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.hashers import check_password
from django.contrib.auth.tokens import default_token_generator

# Rest Framework Imports
from rest_framework.generics import GenericAPIView
from rest_framework import status
from rest_framework.response import Response
from rest_framework import permissions as rest_permissions

# Simple JWT Token
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework_simplejwt.views import TokenRefreshView

# Current app Imports
from . import serializers as auth_serializers
from .helpers import AuthHelper, validation_error_handler
from .tokens import account_activation_token, password_reset_token
from .models import Profile


User = get_user_model()


class SignUpView(GenericAPIView):

    # DRF uses this variable to display the deafult html template
    serializer_class = auth_serializers.CreateUserSerializer

    def post(self, request, *args, **kwargs):
        request_data = request.data
        # data is required - otherwise it will not perform validations
        serializer = self.serializer_class(data=request_data)

        if serializer.is_valid() is False:
            return Response({
                "status": "error",
                # For the toast
                "message": validation_error_handler(serializer.errors),
                "payload": {
                    "errors": serializer.errors
                }
            }, status.HTTP_400_BAD_REQUEST)

        validated_data = serializer.validated_data
        email = validated_data['email']
        password = validated_data['password']

        existing_user = User.objects.filter(email=email).first()

        if existing_user is not None:
            # If verification fails because of third-party apps, user can signup again
            if existing_user.is_active is False:
                existing_user.set_password(password)
                existing_user.save()
                user = existing_user
            else:
                return Response({
                    "stautus": "error",
                    "message": "Account with this email address already exists.",
                    "payload": {},
                }, status=status.HTTP_400_BAD_REQUEST)
        else:
            username = AuthHelper.create_username(email=email)
            
            # Send signal to create user profile
            user = User.objects.create_user(
                username=username,
                is_active=False,
                **validated_data
            )

        serializer_data = self.serializer_class(user).data

        # Email
        # subject = "Verify Email for your account on My App"
        # template = "auth/email/verify_email.html"
        # context_data = {
        #     "host": settings.FRONTEND_HOST,
        #     "uid": urlsafe_base64_encode(force_bytes(user.id)),
        #     "token": account_activation_token.make_token(user=user),
        #     "protocol": settings.FRONTEND_PROTOCOL
        # }

        print(
            f"uid: {urlsafe_base64_encode(force_bytes(user.id))}, token: {account_activation_token.make_token(user=user)}")
        try:
            # Send Verification Email here

            return Response({
                "status": "success",
                "message": "Sent the account verification link to your email address",
                "payload": {
                    **serializer_data,
                    # For log in purpose, If the email is the verified this token will not work.
                    "tokens": AuthHelper.get_tokens_for_user(user)
                }
            }, status=status.HTTP_201_CREATED)
        except Exception:
            # logger.error(
            #     "Some error occurred in signup endpoint", exc_info=True)
            return Response({
                "status": "error",
                "message": "Some error occurred",
                "payload": {}
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ActivateAccountView(GenericAPIView):

    def get(self, request, *args, **kwargs):

        try:
            uidb64 = kwargs['uidb64']
            token = kwargs['token']
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and account_activation_token.check_token(user, token):
            user.is_active = True
            user.save()

            return Response({
                'status': 'success',
                'message': 'account verified',
                'payload': {},
            }, status=status.HTTP_200_OK)

        return Response({
            "status": "error",
            "message": "Activation link is invalid",
            "payload": {}
        }, status=status.HTTP_403_FORBIDDEN)


class LoginView(GenericAPIView):
    serializer_class = auth_serializers.UserLoginSerializer

    def post(self, request, *args, **kwargs):
        request_data = request.data
        serializer = self.serializer_class(data=request_data)
        if serializer.is_valid() is False:
            return Response({
                "status": "error",
                "message": validation_error_handler(serializer.errors),
                "payload": {
                    "errors": serializer.errors
                }
            }, status.HTTP_400_BAD_REQUEST)

        validated_data = serializer.validated_data
        username_or_email = validated_data["username_or_email"]
        password = validated_data["password"]

        user = (
            User.objects.filter(email=username_or_email).first()
            or
            User.objects.filter(username=username_or_email).first()
        )

        if user is not None:
            validate_password = check_password(
                password, user.password
            )
            if validate_password:
                if user.is_active is False:
                    return Response({
                        "status": "error",
                        "message": "User account is not active. Please verify your email first.",
                        "payload": {}
                    }, status=status.HTTP_403_FORBIDDEN)
                serializer_data = self.serializer_class(
                    user, context={"request": request}
                )
                return Response({
                    "status": "success",
                    "message": "Login Successful",
                    "payload": {
                        **serializer_data.data,
                        "token": AuthHelper.get_tokens_for_user(user)
                    }
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    "status": "error",
                    "message": "Invalid Credentials",
                    "payload": {}
                }, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({
                "status": "error",
                "message": "No user found",
                "payload": {}
            }, status=status.HTTP_404_NOT_FOUND)
        

class UserLogoutView(GenericAPIView):

    serializer_class = auth_serializers.LogoutRequestSerializer
    permission_classes = [rest_permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        request_data = request.data
        serializer = self.serializer_class(data=request_data)

        if serializer.is_valid() is False:
            return Response({
                "status": "error",
                "message": validation_error_handler(serializer.errors),
                "payload": {
                    "errors": serializer.errors
                }
            }, status.HTTP_400_BAD_REQUEST)
        validated_data = serializer.validated_data

        try:
            if validated_data.get("all"):
                for token in OutstandingToken.objects.filter(user=request.user):
                    # Returns object and True if the token is present, else False
                    _, _ = BlacklistedToken.objects.get_or_create(token=token)
                    
                return Response({
                    "status": "success",
                    "message": "Successfully logged out from all devices",
                    "payload": {}
                }, status=status.HTTP_200_OK)

            refresh_token = validated_data.get("refresh")

            # Invalidate the refresh token
            token = RefreshToken(token=refresh_token)
            token.blacklist()

            return Response({
                "status": "success",
                "message": "Successfully logged out",
                "payload": {}
            }, status=status.HTTP_200_OK)

        except TokenError:
            return Response({
                "detail": "Token is blacklisted",
                "code": "token_not_valid"
            }, status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "Error occurred",
                "payload": {}
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ChangePasswordView(GenericAPIView):

    serializer_class = auth_serializers.ChangePasswordSerializer
    permission_classes = (rest_permissions.IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        requested_data = request.data

        serializer = self.serializer_class(data=requested_data, context={'request':request})

        if serializer.is_valid() is False:
            return Response({
                "status":"error",
                "message": validation_error_handler(serializer.errors),
                "payload": {
                    "errors":serializer.errors,
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        user = request.user
        validated_data = serializer.validated_data
        old_password = validated_data['old_password']
        new_password = validated_data['new_password']
        confirm_password = validated_data['confirm_password']


        if check_password(old_password, user.password) is False:
            return Response({
                "status":"error",
                "message":"Please enter a correct password.",
                "payload":{},
            }, status=status.HTTP_403_FORBIDDEN)
        
        user.set_password(new_password)
        user.save()

        if settings.LOGOUT_AFTER_PASSWORD_CHANGE is True:
            for token in OutstandingToken.objects.filter(user=user):
                    _, _ = BlacklistedToken.objects.get_or_create(token=token)
                    
        return Response({
            "status": "success",
            "message": "Password changed successfully. Please login with new password.",
            "payload": {}
        }, status=status.HTTP_200_OK)


class PasswordResetView(GenericAPIView):
    serializer_class = auth_serializers.PasswordResetSerializer

    def post(self, request,*args, **kwargs):
        requested_data = request.data

        serializer = self.serializer_class(data=requested_data, context={'request':request})

        if serializer.is_valid() is False:
            return Response({
                "status":"error",
                "message":validation_error_handler(serializer.errors),
                "payload":{},
            }, status=status.HTTP_400_BAD_REQUEST)
        
        email = serializer.validated_data['email']
        try:
            user = User.objects.get(email=email, is_active=True)
        except User.DoesNotExist:
            return Response({
                "status":"error",
                "message":"No user with that email. Please enter your registered email address.",
                "payload":{}
            }, status=status.HTTP_400_BAD_REQUEST)

        if user is not None:
            # Email
            subject = "Verify Email for your account on My App"
            template = "auth/email/password_reset.html"
            context_data = {
                "host": settings.FRONTEND_HOST,
                "uidb64": urlsafe_base64_encode(force_bytes(user.id)),
                "token": default_token_generator.make_token(user=user),
                "protocol": settings.FRONTEND_PROTOCOL
            }
            print(context_data)

            try:
                # Send EMail here
                return Response({
                    "status": "success",
                    "message": "Password Reset Link has been sent to the registered email address",
                    "payload": {}
                }, status=status.HTTP_200_OK)

            except Exception as e:
                return Response({
                    "status": "error",
                    "message": "Some error occurred",
                    "payload": {}
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            

class PasswordResetConfirmView(GenericAPIView):
    serializer_class = auth_serializers.PasswordResetConfirmSerializer

    def post(self, request, uidb64, token, *args, **kwargs):

        requested_data = request.data
        serializer = self.serializer_class(data=requested_data, context={'request':request})
        if serializer.is_valid() is False:
            return Response({
                "status":"error",
                "message":validation_error_handler(serializer.errors),
                "payload":{},
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            new_password = serializer.validated_data['new_password']
            user.set_password(new_password)
            return Response({
                'status': 'success',
                'message': 'Your password has been changed. Please login with your new password.',
                'payload': {},
            }, status=status.HTTP_200_OK)

        return Response({
            "status": "error",
            "message": "Password reset link is invalid.",
            "payload": {}
        }, status=status.HTTP_403_FORBIDDEN)


class CustomTokenRefreshView(TokenRefreshView):
    serializer_class = auth_serializers.CustomTokenRefreshSerializer

    def post(self, request, *args, **kwargs) -> Response:
        return super().post(request, *args, **kwargs)