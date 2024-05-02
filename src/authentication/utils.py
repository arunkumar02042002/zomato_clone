
# Django Imports
from django.conf import settings
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from django.contrib.auth.tokens import default_token_generator

# Current app import
from .tokens import account_activation_token


def send_account_verification_email(user):
    
    subject = "Verify your account on Zomato"
    template_name = "auth/verify_account_email.html"
    context = {
        "host": settings.FRONTEND_HOST,
        "uid": urlsafe_base64_encode(force_bytes(user.id)),
        "token": account_activation_token.make_token(user=user),
        "protocol": settings.FRONTEND_PROTOCOL
    }
    print('Verify context', context)
    message = render_to_string(template_name=template_name, context=context)
    mail = EmailMessage(subject=subject, body=message, from_email=settings.DEFAULT_FROM_EMAIL, to=[user.email])
    mail.send()


def send_password_reset_mail(user):
    
    subject = "Reset your password on Zomato"
    template_name = "auth/password_reset_email.html"
    context = {
        "host": settings.FRONTEND_HOST,
        "uid": urlsafe_base64_encode(force_bytes(user.id)),
        "token": default_token_generator.make_token(user=user),
        "protocol": settings.FRONTEND_PROTOCOL
    }
    print('forget password context', context)
    message = render_to_string(template_name=template_name, context=context)
    mail = EmailMessage(subject=subject, body=message, from_email=settings.DEFAULT_FROM_EMAIL, to=[user.email])
    mail.send()