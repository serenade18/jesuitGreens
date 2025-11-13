import jwt
from rest_framework import authentication, exceptions
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.conf import settings

from greenApp.models import TeamMember


class UnifiedJWTAuthentication(authentication.BaseAuthentication):
    """
    Authenticates both UserAccount (via SimpleJWT) and TeamMember (via custom JWT).
    """
    def authenticate(self, request):
        auth_header = authentication.get_authorization_header(request).decode('utf-8')

        if not auth_header or not auth_header.startswith('Bearer '):
            return None

        token = auth_header.split(' ')[1]

        # Try SimpleJWT first
        simplejwt_auth = JWTAuthentication()
        try:
            validated_token = simplejwt_auth.get_validated_token(token)
            user = simplejwt_auth.get_user(validated_token)
            return (user, token)
        except Exception:
            pass  # If SimpleJWT fails, try TeamMember token

        # Try TeamMember token
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed("Token expired.")
        except jwt.InvalidTokenError:
            raise exceptions.AuthenticationFailed("Invalid token.")

        if payload.get("user_type") == "team_member":
            try:
                team_member = TeamMember.objects.get(id=payload["id"])
                return (team_member, token)
            except TeamMember.DoesNotExist:
                raise exceptions.AuthenticationFailed("Team member not found.")

        # No valid token
        raise exceptions.AuthenticationFailed("Authentication failed.")
