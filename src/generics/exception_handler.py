
from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
from rest_framework.exceptions import ValidationError

from .helpers import validation_error_handler

def custom_exception_handler(exc, context):
    # Call REST framework's default exception handler first,
    # to get the standard error response.
    response = exception_handler(exc, context)

    if isinstance(exc, ValidationError):
        response = Response({
            "status": "error",
            "message": validation_error_handler(exc.detail),
            "payload": {
                "error": exc.detail
            }
        }, status=status.HTTP_400_BAD_REQUEST)
    elif response is not None:
        # For other types of exceptions
        response.data = {
            "status": "error",
            "message": response.data.get('detail', 'An error occurred.'),
            "payload": {}
        }

    return response
