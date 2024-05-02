from django.urls import path

from generics.views import UploadRestaurantLicenseView

urlpatterns = [
    path('license-upload/', UploadRestaurantLicenseView.as_view(), name='restaurants-license-upload'),
]
