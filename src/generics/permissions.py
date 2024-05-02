
from authentication.models import UserTypeChoices

from rest_framework.permissions import BasePermission

class IsAdminUserOrRestaurant(BasePermission):
    """
    Allows access only to staff users and restaurant users.
    """

    def has_permission(self, request, view):

        return bool(request.user and request.user.is_staff or request.user.user_type==UserTypeChoices.RESTAURANT)