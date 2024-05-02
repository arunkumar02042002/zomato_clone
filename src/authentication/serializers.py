# Django Imports
from django.contrib.auth import get_user_model
from django.core.validators import EmailValidator
from django.contrib.auth.password_validation import validate_password
from django.conf import settings

# Rest Framework Imports
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
from rest_framework_simplejwt.utils import datetime_from_epoch


# Others
import os

User = get_user_model()


class CreateUserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = [
            "email",
            "password",
            "user_type",
        ]

        read_only_fields = ["user_type"]

        # Use this to define which variables are read only and write_only
        extra_kwargs = {
            "password": {"write_only": True},
            'email': {
                'validators': [EmailValidator]
            }
        }

    # Naming convention - validate_ followed by field name
    def validate_password(self, value):
        validate_password(value)
        return value

    def validate_email(self, value):
        lower_case_email = value.lower()
        return lower_case_email


class RegisterRestaurantSerializer(serializers.Serializer):
    first_name = serializers.CharField(max_length=255)
    last_name = serializers.CharField(max_length=255)
    email = serializers.EmailField()
    password = serializers.CharField(max_length=255)
    license = serializers.CharField(max_length=255)
    restaurant_name = serializers.CharField(max_length=255)

    class Meta:
        extra_kwargs = {
            'email': {
                'validators': [EmailValidator]
            }
        }

    # Naming convention - validate_ followed by field name
    def validate_password(self, value):
        validate_password(value)
        return value

    def validate_email(self, value):
        lower_case_email = value.lower()
        return lower_case_email
    
    def validate_license(self, value):
        """
        Validate that the license path points to an existing file.
        """
        path = os.path.join(settings.MEDIA_ROOT, value)
        if not os.path.isfile(path):
            raise serializers.ValidationError("Invalid license image path provided.")
        return value


class UserLoginSerializer(serializers.ModelSerializer):
    username_or_email = serializers.CharField(
        write_only=True
    )

    class Meta:
        model = User
        fields = (
            "username_or_email",
            "email",
            "password",
            "username",
            "user_type",
            "first_name",
            "last_name",
            "date_joined",
            "is_active",
            "is_superuser"
        )
        read_only_fields = [
            "email",
            "username",
            "user_type",
            "first_name",
            "last_name",
            "date_joined",
            "is_active",
            "is_superuser"
        ]
        extra_kwargs = {
            "password": {"write_only": True}
        }

    def validate_username_or_email(self, value):
        return value.lower()


class LogoutRequestSerializer(serializers.Serializer):

    # Refresh is required - But setting required=False beacuse I want to give the custom message before the serializers sends it validation error message.
    all = serializers.BooleanField(required=False)
    refresh = serializers.CharField(required=False)

    def validate(self, attrs):
        all = attrs.get('all')
        refresh = attrs.get('refresh')

        if all is None:
            if refresh is None:
                raise serializers.ValidationError(
                    {
                        "refresh": "If the user wants to logout from all devices then all parameter must be passed with true else refresh is required to logout from the current device."
                    }
                )
        return super().validate(attrs=attrs)
    

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    new_password = serializers.CharField()
    confirm_password = serializers.CharField()

    def validate(self, attrs):

        old_password = attrs.get('old_password')
        new_password = attrs.get('new_password')
        confirm_password = attrs.get('confirm_password')

        if not old_password:
            raise serializers.ValidationError({
                "old_password":"Current Password can't be empty."
            })
    
        if not new_password:
            raise serializers.ValidationError({
                "new_password":"New Password can't be empty."
            })
        
        if not confirm_password:
            raise serializers.ValidationError({
                "confirm_password":"Confirm Password can't be empty."
            })
        
        if not confirm_password == new_password:
            raise serializers.ValidationError({
                "confim_password":"Confirm Password and New Password must be same."
            })
        
        if new_password == old_password:
            raise serializers.ValidationError({
                "new_password":"You new password can't be same as your previour password."
            })

        return super().validate(attrs=attrs)

 
class PasswordResetSerializer(serializers.Serializer):

    email = serializers.EmailField(required=True)

    extra_kwargs = {
        'email': {
            'validators': [EmailValidator]
        }
    }

    def validate_email(self, email):
        lower_case_email = email.lower()
        return lower_case_email
    

class PasswordResetConfirmSerializer(serializers.Serializer):
    new_password = serializers.CharField(required=True)
    confirm_password = serializers.CharField(required=True)

    def validate(self, attrs):
        confirm_password = attrs['confirm_password']
        new_password = attrs['new_password']

        if not confirm_password == new_password:
            raise serializers.ValidationError({
                "error":"Confirm Password and New Password must be same."
            })

        return super().validate(attrs=attrs)


class CustomTokenRefreshSerializer(TokenRefreshSerializer):
    def validate(self, attrs):
        try:
            refresh = RefreshToken(attrs["refresh"])
            data = {"access": str(refresh.access_token)}
            if settings.SIMPLE_JWT["ROTATE_REFRESH_TOKENS"]:
                payload = refresh.payload
                id = payload["user_id"]
                user = User.objects.get(id=id)

                if not settings.ALLOW_NEW_REFRESH_TOKENS_FOR_UNVERIFIED_USERS:
                    
                    if user.is_active == False:
                        raise TokenError(
                            {"details": "User is inactive", "code": "user_inactive"})

                if settings.SIMPLE_JWT["BLACKLIST_AFTER_ROTATION"]:
                    try:
                        refresh.blacklist()
                    except AttributeError:
                        pass

                # Creating new access tokens
                refresh.set_jti()
                refresh.set_exp()

                if settings.SIMPLE_JWT["BLACKLIST_AFTER_ROTATION"]:
                    OutstandingToken.objects.create(
                        user=user,
                        jti=payload[settings.SIMPLE_JWT["JTI_CLAIM"]],
                        token=str(refresh),
                        created_at=refresh.current_time,
                        expires_at=datetime_from_epoch(payload["exp"]),
                    )

                data["refresh"] = str(refresh)
            return data
        except TokenError as e:
            raise

        except serializers.ValidationError:
            raise

        except Exception:
            raise