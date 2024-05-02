from django.shortcuts import render


from rest_framework.generics import GenericAPIView, UpdateAPIView
from rest_framework import permissions as rest_permissions
from rest_framework.response import Response
from rest_framework import status


from generics.helpers import validation_error_handler


from .models import Restaurant
from . import serializers as restaurant_serializers


# Create your views here.

class RestarauntApprovAndDisapproveAdminView(GenericAPIView):
    permission_classes = (rest_permissions.IsAuthenticated, rest_permissions.IsAdminUser)
    serializer_class = restaurant_serializers.RestaurantSerializer
    queryset = Restaurant.objects.all()

    def post(self, request, pk, *args, **kwargs):
        serilaizer = self.serializer_class(data=request.data)

        if serilaizer.is_valid() is False:
            return Response({
                "status":"error",
                "message": validation_error_handler(serilaizer.errors),
                "payload": {
                    "error":serilaizer.errors
                }
            }, status=status.HTTP_400_BAD_REQUEST)
        
        is_approved = serilaizer.validated_data['is_approved']

        restaurant = self.queryset.filter(id=pk).first()

        if restaurant:
            restaurant.is_approved = is_approved
            restaurant.save()

            serilaizer = self.serializer_class(restaurant)

            if restaurant.is_approved:
                # send apporval mail here

                return Response({
                    "status":"success",
                    "message":"Restaurant successfully approved!",
                    "payload": serilaizer.data
                }, status=status.HTTP_200_OK)
            
            else:
                # send disapproval mail here

                return Response({
                    "status":"success",
                    "message":"Restaurant successfully disapproved!",
                    "payload": serilaizer.data
                }, status=status.HTTP_200_OK)
            
        return Response({
            "status":"error",
            "message":"Invalid primary key.",
            "payload": {}
        }, status=status.HTTP_400_BAD_REQUEST)