
from rest_framework import serializers


class LicenseUploadSerializer(serializers.Serializer):

    license = serializers.ImageField()