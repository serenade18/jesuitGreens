import jwt
from datetime import datetime, timedelta

from django.contrib.auth.hashers import make_password, check_password
from django.shortcuts import render, get_object_or_404
from rest_framework import viewsets, status
from rest_framework.exceptions import ValidationError, PermissionDenied, AuthenticationFailed
from rest_framework.permissions import IsAuthenticated, AllowAny, BasePermission
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import action
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from jwt import ExpiredSignatureError, InvalidTokenError

from greenProject import settings
from greenApp.models import UserAccount, TeamRoles, Farm, NotificationPreference, Notification, TeamMember, \
    LeaveRequest, Salary
from greenApp.permissions import IsAdminRole, IsFarmManagerRole, IsTeamMemberRole
from greenApp.serializers import UserAccountSerializer, UserCreateSerializer, TeamRolesSerializer, FarmSerializer, \
    NotificationPreferenceSerializer, NotificationSerializer, TeamSerializer, LeaveRequestSerializer, SalarySerializer, \
    SalaryDetailSerializer


# Create your views here.

def encode_manual_token(payload: dict, lifetime: timedelta, algorithm="HS256") -> str:
    now = datetime.utcnow()
    token_payload = payload.copy()
    token_payload["iat"] = int(now.timestamp())
    token_payload["exp"] = int((now + lifetime).timestamp())
    token = jwt.encode(token_payload, settings.SECRET_KEY, algorithm=algorithm)
    return token if isinstance(token, str) else token.decode("utf-8")


def decode_manual_token(token: str, verify_exp=True) -> dict:
    """Decode a manual TeamMember JWT"""
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"], options={"verify_exp": verify_exp})
    except jwt.ExpiredSignatureError:
        raise AuthenticationFailed("Manual token expired")
    except jwt.InvalidTokenError:
        raise AuthenticationFailed("Invalid manual token")

def decode_team_member_token(token: str):
    try:
        decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        if decoded.get("user_type") != "team_member":
            raise AuthenticationFailed("Token is not for a team member")
        team_member = TeamMember.objects.get(id=decoded["id"], is_active=True)
        return team_member, "team_member"
    except jwt.ExpiredSignatureError:
        raise AuthenticationFailed("Team member token expired")
    except jwt.InvalidTokenError:
        raise AuthenticationFailed("Invalid team member token")
    except TeamMember.DoesNotExist:
        raise AuthenticationFailed("Team member not found")

# Decode UserAccount via SimpleJWT
def decode_user_account_token(token: str):
    jwt_auth = JWTAuthentication()
    try:
        validated_token = jwt_auth.get_validated_token(token)
        user = jwt_auth.get_user(validated_token)
        return user, "user_account"
    except Exception:
        raise AuthenticationFailed("Invalid UserAccount token")

# Unified get_authenticated_user
def get_authenticated_user(request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise AuthenticationFailed("Missing or invalid authorization header")

    token = auth_header.split(" ")[1]

    # Try TeamMember first
    try:
        return decode_team_member_token(token)
    except AuthenticationFailed:
        # Not a TeamMember token, fallback to UserAccount
        return decode_user_account_token(token)


# --- Login ---
class LoginViewSet(viewsets.ViewSet):
    permission_classes = [AllowAny]

    def create(self, request):
        email = request.data.get("email")
        password = request.data.get("password")
        if not email or not password:
            return Response({"error": True, "message": "Email and password are required"},
                            status=status.HTTP_400_BAD_REQUEST)

        # 1️⃣ UserAccount login
        try:
            user = UserAccount.objects.get(email=email)
            if user.check_password(password):
                token = RefreshToken.for_user(user)
                return Response({
                    "access": str(token.access_token),
                    "refresh": str(token),
                }, status=status.HTTP_200_OK)
        except UserAccount.DoesNotExist:
            pass

        # 2️⃣ TeamMember login
        try:
            team_member = TeamMember.objects.get(email=email, is_active=True)
            if check_password(password, team_member.password):
                access_payload = {"id": team_member.id, "email": team_member.email, "user_type": "team_member"}
                refresh_payload = {"id": team_member.id, "email": team_member.email,
                                   "user_type": "team_member", "type": "refresh"}

                access_token = encode_manual_token(access_payload, timedelta(hours=1))
                refresh_token = encode_manual_token(refresh_payload, timedelta(days=7))
                return Response({"access": access_token, "refresh": refresh_token}, status=status.HTTP_200_OK)
        except TeamMember.DoesNotExist:
            pass

        return Response({"error": True, "message": "Invalid email or password"}, status=status.HTTP_401_UNAUTHORIZED)


# --- Refresh ---
class UnifiedRefreshView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response({"error": True, "message": "Refresh token is required"}, status=400)

        # SimpleJWT refresh
        try:
            token = RefreshToken(refresh_token)
            return Response({"access": str(token.access_token)}, status=status.HTTP_200_OK)
        except Exception:
            pass

        # Manual TeamMember refresh
        try:
            decoded = decode_manual_token(refresh_token)
            if decoded.get("user_type") == "team_member" and decoded.get("type") == "refresh":
                new_access_token = encode_manual_token(
                    {"id": decoded["id"], "email": decoded["email"], "user_type": "team_member"},
                    timedelta(hours=1)
                )
                return Response({"access": new_access_token}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": True, "message": str(e)}, status=401)

        return Response({"error": True, "message": "Invalid or unsupported refresh token"}, status=400)


# --- User Info ---
class UserInfoView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = UserAccountSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        """Full update of logged-in user's profile"""
        user = request.user
        serializer = UserAccountSerializer(user, data=request.data)
        if serializer.is_valid():
            # Handle password hashing if updated
            if "password" in serializer.validated_data:
                serializer.validated_data["password"] = make_password(serializer.validated_data["password"])
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request):
        """Partial update of logged-in user's profile"""
        user = request.user
        serializer = UserAccountSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            if "password" in serializer.validated_data:
                serializer.validated_data["password"] = make_password(serializer.validated_data["password"])
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        """Allow logged-in user to delete their own account"""
        user = request.user
        user.delete()
        return Response({"message": "Account deleted successfully"}, status=status.HTTP_204_NO_CONTENT)


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        current_password = request.data.get("current_password")
        new_password = request.data.get("new_password")

        if not current_password or not new_password:
            return Response(
                {"error": "Both current_password and new_password are required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not user.check_password(current_password):
            return Response(
                {"error": "Current password is incorrect"},
                status=status.HTTP_400_BAD_REQUEST
            )

        user.set_password(new_password)
        user.save()

        return Response({"message": "Password updated successfully"}, status=status.HTTP_200_OK)


class UserViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [AllowAny],
        'list': [IsAdminRole],
        'default': [IsAuthenticated]
    }

    def get_permissions(self):
        return [permission() for permission in
                self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])]

    def list(self, request):
        try:
            users = UserAccount.objects.all()
            serializer = UserAccountSerializer(users, many=True, context={"request": request})
            response_data = serializer.data
            response_dict = {"error": False, "message": "All Users List Data", "data": response_data}
        except ValidationError as e:
            response_dict = {"error": True, "message": "Validation Error", "details": str(e)}
        except Exception as e:
            response_dict = {"error": True, "message": "An Error Occurred", "details": str(e)}

        return Response(
            response_dict,
            status=status.HTTP_400_BAD_REQUEST if response_dict['error'] else status.HTTP_200_OK
        )

    def create(self, request):
        serializer = UserCreateSerializer(data=request.data)
        if serializer.is_valid():
            # Hash the password
            password = make_password(serializer.validated_data['password'])
            serializer.validated_data['password'] = password

            # Directly activate the user
            serializer.validated_data['is_active'] = True
            serializer.save()

            return Response(
                {"message": "User account created successfully"},
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        queryset = UserAccount.objects.all()
        user = get_object_or_404(queryset, pk=pk)
        serializer = UserAccountSerializer(user)
        return Response(serializer.data)

    def update(self, request, pk=None):
        user = get_object_or_404(UserAccount, pk=pk)

        # Permission check
        if request.user.role != "super_admin" and request.user.pk != user.pk:
            raise PermissionDenied("You can only update your own account.")

        serializer = UserAccountSerializer(user, data=request.data)
        if serializer.is_valid():
            # Handle password hashing if updated
            if "password" in serializer.validated_data:
                serializer.validated_data["password"] = make_password(serializer.validated_data["password"])
            serializer.save()
            return Response(serializer.data)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        user = get_object_or_404(UserAccount, pk=pk)

        # Permission check
        if request.user.role != "super_admin" and request.user.pk != user.pk:
            raise PermissionDenied("You can only update your own account.")

        serializer = UserAccountSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            if "password" in serializer.validated_data:
                serializer.validated_data["password"] = make_password(serializer.validated_data["password"])
            serializer.save()
            return Response(serializer.data)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        user = get_object_or_404(UserAccount, pk=pk)

        # Permission check
        if request.user.role != "super_admin" and request.user.pk != user.pk:
            raise PermissionDenied("You can only delete your own account.")

        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# Team roles
class TeamRolesViewSet(viewsets.ModelViewSet):
    permission_classes_by_action = {
        'create': [IsFarmManagerRole, IsAdminRole],
        'list': [AllowAny],
        'destroy': [IsFarmManagerRole, IsAdminRole],
        'update': [IsFarmManagerRole, IsAdminRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])
        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def list(self, request):
        try:
            roles = TeamRoles.objects.all().order_by('-id')
            serializer = TeamRolesSerializer(roles, many=True)
            return Response({
                "error": False,
                "message": "All Roles Data",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request):
        serializer = TeamRolesSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "error": False,
                "message": "Role created successfully",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)
        return Response({
            "error": True,
            "message": "Validation failed",
            "details": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        role = get_object_or_404(TeamRoles, pk=pk)
        serializer = TeamRolesSerializer(role)
        return Response({
            "error": False,
            "message": "Role retrieved successfully",
            "data": serializer.data
        })

    def update(self, request, pk=None):
        try:
            role = get_object_or_404(TeamRoles, pk=pk)
            serializer = TeamRolesSerializer(role, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Role updated successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)
            return Response({
                "error": True,
                "message": "Validation failed",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        try:
            role = get_object_or_404(TeamRoles, pk=pk)
            role.delete()
            return Response({
                "error": False,
                "message": "Role deleted successfully"
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


# Farm settings
class FarmViewSet(viewsets.ModelViewSet):
    permission_classes_by_action = {
        'create': [IsFarmManagerRole],
        'list': [IsAdminRole, IsFarmManagerRole],
        'destroy': [IsFarmManagerRole, IsAdminRole],
        'update': [IsFarmManagerRole, IsAdminRole],
        'retrieve': [IsFarmManagerRole, IsAdminRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])
        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def list(self, request):
        try:
            user = request.user

            if IsAdminRole().has_permission(request, self):
                farm = Farm.objects.all().order_by("-id")
            else:
                farm = Farm.objects.filter(user_id=user).order_by("-id")
            serializer = FarmSerializer(farm, many=True)
            return Response({
                "error": False,
                "message": "All farms Data",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request, *args, **kwargs):
        serializer = FarmSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user_id=request.user)
            return Response({
                "error": False,
                "message": "Farm created successfully",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)
        return Response({
            "error": True,
            "message": "Validation failed",
            "details": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        farm = get_object_or_404(Farm, pk=pk)
        serializer = FarmSerializer(farm)
        return Response({
            "error": False,
            "message": "Farm retrieved successfully",
            "data": serializer.data
        })

    def update(self, request, pk=None):
        try:
            farm = get_object_or_404(Farm, pk=pk)
            serializer = FarmSerializer(farm, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Farm updated successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)
            return Response({
                "error": True,
                "message": "Validation failed",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        try:
            farm = get_object_or_404(Farm, pk=pk)
            farm.delete()
            return Response({
                "error": False,
                "message": "Farm deleted successfully"
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


# Notifications settings
class NotificationPreferenceViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def list(self, request):
        try:
            prefs, _ = NotificationPreference.objects.get_or_create(user=request.user)
            serializer = NotificationPreferenceSerializer(prefs)
            return Response({
                "error": False,
                "message": "Notification preferences retrieved successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=["patch", "put"], url_path="update")
    def update_preferences(self, request):
        prefs, _ = NotificationPreference.objects.get_or_create(user=request.user)
        serializer = NotificationPreferenceSerializer(prefs, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "error": False,
                "message": "Notifications updated",
                "data": serializer.data
            })
        return Response({
            "error": True,
            "message": "Validation failed",
            "details": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


# Notifications
class NotificationsViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def list(self, request):
        filter_param = request.query_params.get("filter", "all")
        
        notice = Notification.objects.all()
        if filter_param == "unread":
            notice = notice.filter(read=False)

        notice = notice.order_by("-added_on")
        serializer = NotificationSerializer(notice, many=True)

        return Response({
            "error": False,
            "message": "Notifications retrieved successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def retrieve(self, request, pk=None):
        try:
            notice = Notification.objects.get(pk=pk, user=request.user)
            serializer = NotificationSerializer(notice)
            return Response({
                "error": False,
                "message": "Notification retrieved successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Notification.DoesNotExist:
            return Response({
                "error": True,
                "message": "Notification not found"
            }, status=status.HTTP_404_NOT_FOUND)

    @action(detail=True, methods=["post"])
    def mark_as_read(self, request, pk=None):
        try:
            notice = Notification.objects.get(pk=pk, user=request.user)
            notice.read = True
            notice.save()
            serializer = NotificationSerializer(notice)
            return Response({
                "error": False,
                "message": "Notification marked as read",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Notification.DoesNotExist:
            return Response({
                "error": True,
                "message": "Notification not found"
            }, status=status.HTTP_404_NOT_FOUND)

    @action(detail=False, methods=["post"])
    def mark_all_as_read(self, request):
        updated_count = Notification.objects.filter(user=request.user, read=False).update(read=True)
        return Response({
            "error": False,
            "message": f"{updated_count} notifications marked as read"
        }, status=status.HTTP_200_OK)

    def destroy(self, request, pk=None):
        try:
            notice = Notification.objects.get(pk=pk, user=request.user)
            notice.delete()
            return Response({
                "error": False,
                "message": "Notification deleted successfully"
            }, status=status.HTTP_200_OK)
        except Notification.DoesNotExist:
            return Response({
                "error": True,
                "message": "Notification not found"
            }, status=status.HTTP_404_NOT_FOUND)


# Team Members
class TeamMembersViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [IsFarmManagerRole],
        'list': [IsAdminRole, IsFarmManagerRole],
        'destroy': [IsFarmManagerRole, IsAdminRole],
        'update': [IsFarmManagerRole, IsAdminRole],
        'retrieve': [IsFarmManagerRole, IsAdminRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def list(self, request):
        try:
            user = request.user
            if IsAdminRole().has_permission(request, self):
                team = TeamMember.objects.all().order_by("-id")
            else:
                team = TeamMember.objects.filter(user=user).order_by("-id")
            serializer = TeamSerializer(team, many=True)
            return Response({
                "error": False,
                "message": "All Team Members",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request):
        try:
            data = request.data.copy()
            data['user'] = request.user.id  # link to the farm admin creating the member

            if 'password' in data and data['password']:
                raw_password = data['password']
                data['password'] = make_password(raw_password)  # hash password
            else:
                return Response({
                    "error": True,
                    "message": "Password is required"
                }, status=status.HTTP_400_BAD_REQUEST)

            serializer = TeamSerializer(data=data)
            if serializer.is_valid():
                team_member = serializer.save()

                # Create corresponding UserAccount
                user_account, created = UserAccount.objects.get_or_create(
                    email=team_member.email,
                    name=team_member.name,
                    phone=team_member.phone,
                    defaults={
                        "password": make_password(request.data["password"]),
                        "role": "farm_worker",
                    }
                )

                return Response({
                    "error": False,
                    "message": "Team Member Created Successfully",
                    "data": serializer.data
                }, status=status.HTTP_201_CREATED)

            return Response({
                "error": True,
                "message": "Validation Failed",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        try:
            member = TeamMember.objects.get(pk=pk)
            serializer = TeamSerializer(member)
            return Response({
                "error": False,
                "message": "Team Member Details",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except TeamMember.DoesNotExist:
            return Response({
                "error": True,
                "message": "Team Member Not Found"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        try:
            member = TeamMember.objects.get(pk=pk)
            data = request.data.copy()
            if 'password' in data and data['password']:
                data['password'] = make_password(data['password'])
            serializer = TeamSerializer(member, data=data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Team Member Updated Successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    "error": True,
                    "message": "Validation Failed",
                    "details": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
        except TeamMember.DoesNotExist:
            return Response({
                "error": True,
                "message": "Team Member Not Found"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        try:
            member = TeamMember.objects.get(pk=pk)

            # Delete corresponding UserAccount (if it exists)
            UserAccount.objects.filter(email=member.email).delete()

            member.delete()
            return Response({
                "error": False,
                "message": "Team Member Deleted Successfully"
            }, status=status.HTTP_200_OK)

        except TeamMember.DoesNotExist:
            return Response({
                "error": True,
                "message": "Team Member Not Found"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


# Leave requests
class LeaveRequestViewSet(viewsets.ModelViewSet):
    serializer_class = LeaveRequestSerializer

    permission_classes_by_action = {
        'create': [IsFarmManagerRole, IsAdminRole, IsTeamMemberRole],
        'list': [IsAdminRole, IsFarmManagerRole, IsTeamMemberRole],
        'destroy': [IsFarmManagerRole, IsAdminRole],
        'update': [IsFarmManagerRole, IsAdminRole],
        'retrieve': [IsFarmManagerRole, IsAdminRole, IsTeamMemberRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def get_queryset(self):
        user = self.request.user
        if IsAdminRole().has_permission(self.request, self):
            # Admin sees all leave requests
            return LeaveRequest.objects.all().order_by("-id")
        elif IsFarmManagerRole().has_permission(self.request, self):
            # Farm Admin sees all leaves of their associated team members
            return LeaveRequest.objects.filter(team_member__user=user).order_by("-id")
        else:
            # Regular team member sees only their own leaves
            return LeaveRequest.objects.filter(team_member__user=user, team_member__email=user.email).order_by("-id")

    def list(self, request, *args, **kwargs):
        try:
            leaves = self.get_queryset()
            serializer = LeaveRequestSerializer(leaves, many=True)
            return Response({
                "error": False,
                "message": "All Leave Requests",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request, *args, **kwargs):
        try:
            user = request.user

            # Find matching team member
            try:
                team_member = TeamMember.objects.get(email=user.email)
            except TeamMember.DoesNotExist:
                return Response({
                    "error": True,
                    "message": "Team member record not found for this user.",
                }, status=status.HTTP_400_BAD_REQUEST)

            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            start_date = serializer.validated_data["start_date"]
            end_date = serializer.validated_data["end_date"]

            if start_date > end_date:
                return Response({
                    "error": True,
                    "message": "End date cannot be earlier than start date.",
                }, status=status.HTTP_400_BAD_REQUEST)

            # Prevent overlapping leave requests
            overlap = LeaveRequest.objects.filter(
                team_member=team_member,
                start_date__lte=end_date,
                end_date__gte=start_date
            ).exists()

            if overlap:
                return Response({
                    "error": True,
                    "message": "You already have a leave request in this date range.",
                }, status=status.HTTP_400_BAD_REQUEST)

            # Calculate days
            days = (end_date - start_date).days + 1

            # Create leave request
            leave = LeaveRequest.objects.create(
                team_member=team_member,
                leave_type=serializer.validated_data["leave_type"],
                start_date=start_date,
                end_date=end_date,
                days=days,
                status="Pending",
            )

            # CREATE NOTIFICATION
            Notification.objects.create(
                user=user,
                title="Leave Request Submitted",
                message=f"Leave request for {start_date} to {end_date} ({days} days) has been submitted successfully.",
                type="success",
                category="team"
            )

            return Response({
                "error": False,
                "message": "Leave Request Created",
                "data": LeaveRequestSerializer(leave).data
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An error occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, *args, **kwargs):
        try:
            leave = self.get_object()
            serializer = self.get_serializer(leave)
            return Response({
                "error": False,
                "message": "Leave Request Details",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        try:
            leave = self.get_object()
            serializer = self.get_serializer(leave, data=request.data, partial=False)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({
                "error": False,
                "message": "Leave Request Updated",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, *args, **kwargs):
        try:
            leave = self.get_object()
            serializer = self.get_serializer(leave, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({
                "error": False,
                "message": "Leave Request Partially Updated",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        try:
            leave = self.get_object()
            leave.delete()
            return Response({
                "error": False,
                "message": "Leave Request Deleted",
                "data": None
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=["patch"], url_path="approve", permission_classes=[IsFarmManagerRole, IsAdminRole])
    def approve(self, request, pk=None):
        try:
            leave = self.get_object()
            leave.status = "Approved"
            leave.save()
            serializer = self.get_serializer(leave)
            return Response({
                "error": False,
                "message": "Leave Request Approved",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "Could not approve leave",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=["patch"], url_path="reject", permission_classes=[IsFarmManagerRole, IsAdminRole])
    def reject(self, request, pk=None):
        try:
            leave = self.get_object()
            leave.status = "Rejected"
            leave.save()
            serializer = self.get_serializer(leave)
            return Response({
                "error": False,
                "message": "Leave Request Rejected",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "Could not reject leave",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


# Salaries
class SalaryViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [IsFarmManagerRole],
        'list': [IsAdminRole, IsFarmManagerRole],
        'retrieve': [IsFarmManagerRole, IsAdminRole],
        'update': [IsFarmManagerRole, IsAdminRole],
        'partial_update': [IsFarmManagerRole, IsAdminRole],
        'destroy': [IsFarmManagerRole, IsAdminRole],
        'default': [IsAuthenticated],
    }

    def get_permissions(self):
        perms = self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])

        def has_any_permission(request, view):
            return any(p().has_permission(request, view) for p in perms)

        class AnyPermission(BasePermission):
            def has_permission(self, request, view):
                return has_any_permission(request, view)

        return [AnyPermission()]

    def list(self, request):
        try:
            user = request.user
            if IsAdminRole().has_permission(request, self):
                salaries = Salary.objects.all().order_by("-id")
            else:
                salaries = Salary.objects.filter(employee__user=user).order_by("-id")

            serializer = SalarySerializer(salaries, many=True)
            return Response({
                "error": False,
                "message": "All Salaries",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        try:
            salary = get_object_or_404(Salary, pk=pk)
            serializer = SalaryDetailSerializer(salary)
            return Response({
                "error": False,
                "message": "Salary Details",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request):
        try:
            member_id = request.data.get("employee")
            if not member_id:
                return Response({
                    "error": True,
                    "message": "Team member is required"
                }, status=status.HTTP_400_BAD_REQUEST)

            # Get the member
            member = get_object_or_404(TeamMember, id=member_id)

            # Get the role name from Role model
            if not member.role:
                return Response({
                    "error": True,
                    "message": "Selected team member has no role assigned"
                }, status=status.HTTP_400_BAD_REQUEST)

            role_name = member.role.role_name  # <-- Fetch role_name via role ID

            # Inject into request data
            data = request.data.copy()
            data["role"] = role_name  # <-- Save role name in salary

            serializer = SalarySerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Salary Created Successfully",
                    "data": serializer.data
                }, status=status.HTTP_201_CREATED)

            return Response({
                "error": True,
                "message": "Validation Failed",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        try:
            salary = get_object_or_404(Salary, pk=pk)
            serializer = SalarySerializer(salary, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "error": False,
                    "message": "Salary Updated Successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)
            return Response({
                "error": True,
                "message": "Validation Failed",
                "details": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        try:
            salary = get_object_or_404(Salary, pk=pk)
            salary.delete()
            return Response({
                "error": False,
                "message": "Salary Deleted Successfully"
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "error": True,
                "message": "An Error Occurred",
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
