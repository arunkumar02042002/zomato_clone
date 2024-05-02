from django.urls import path

from restaurants import views as restaurant_views


urlpatterns = [
    path("restaurants/<int:pk>/approve-disapprove/", view=restaurant_views.RestarauntApprovAndDisapproveAdminView.as_view(), name="approve-disapprove-restaurant")
]
