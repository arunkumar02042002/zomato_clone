
# Django Imports
from django.shortcuts import render

# third-party apps import
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework import permissions
from rest_framework import parsers
from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

# Current apps imports
from . import permissions as generic_permissions
from . import serializers as generic_serializers


from generics.helpers import validation_error_handler

# Other
import os
import uuid

# Create your views here.
class UploadRestaurantLicenseView(GenericAPIView):

    parser_classes = (parsers.MultiPartParser,)
    serializer_class = generic_serializers.LicenseUploadSerializer

    def post(self, request, *args, **kwargs):

        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid() is False:
            return Response({
                "status":"error",
                "message":validation_error_handler(serializer.errors),
                "payload":{
                    "errors":serializer.errors
                }
            }, status=status.HTTP_400_BAD_REQUEST)
        
        license = serializer.validated_data['license']            
        license_name = os.path.splitext(license.name)[0]
        license_extension = os.path.splitext(license.name)[1]

        if not license or license_extension.lower() not in {'.jpg', '.png'}:
            return Response({
                "status":"error",
                "message":"jpg and png are only supported format.",
                "payload":{}
            }, status=status.HTTP_400_BAD_REQUEST)

        save_path = "media/restaurants/license/"
        if not os.path.exists(save_path):
            os.makedirs(os.path.dirname(save_path), exist_ok=True)

        license_name = license_name + str(uuid.uuid4())
        license_save_path = "%s/%s%s" % (save_path, license_name, license_extension)
        response_url = "restaurants/license/" + license_name + license_extension

        with open(license_save_path, "wb+") as f:
            for chunk in license.chunks():
                f.write(chunk)

        return Response({
            "status":"success",
            "message":"License uploaded successfully.",
            "payload":{
                "license": response_url
            }
        }, status=status.HTTP_200_OK)
    
