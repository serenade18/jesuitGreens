from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model

User = get_user_model()

class EmailOrUsernameBackend(ModelBackend):
    """
    Allows login with either username or email.
    """
    def authenticate(self, request, username=None, password=None, **kwargs):
        login_value = username or kwargs.get("username") or kwargs.get("email")
        if not login_value or not password:
            return None

        # Try username first
        try:
            user = User.objects.get(username=login_value)
        except User.DoesNotExist:
            user = None

        # If no username match, try email
        if user is None:
            try:
                user = User.objects.get(email=login_value)
            except User.DoesNotExist:
                return None

        if user.check_password(password) and user.is_active:
            return user
        return None
