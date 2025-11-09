from rest_framework.permissions import BasePermission

class IsAdminRole(BasePermission):
    """
    Allows access only to users with usertype='admin'
    """
    def has_permission(self, request, view):
        return bool(
            request.user
            and request.user.is_authenticated
            and getattr(request.user, "role", None) == "super_admin"
        )

class IsFarmManagerRole(BasePermission):

    def has_permission(self, request, view):
        return bool(
            request.user
            and request.user.is_authenticated
            and getattr(request.user, "role", None) == "farm_admin"
        )
