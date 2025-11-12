from django.contrib.auth.hashers import make_password
from django.shortcuts import render, get_object_or_404
from rest_framework import viewsets, status
from rest_framework.exceptions import ValidationError, PermissionDenied
from rest_framework.permissions import IsAuthenticated, AllowAny, BasePermission
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import action

from greenApp.models import UserAccount, TeamRoles, Farm, NotificationPreference, Notification
from greenApp.permissions import IsAdminRole, IsFarmManagerRole
from greenApp.serializers import UserAccountSerializer, UserCreateSerializer, TeamRolesSerializer, FarmSerializer, \
    NotificationPreferenceSerializer, NotificationSerializer


# Create your views here.

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
        notice = Notification.objects.filter(user=request.user).order_by("-added_on")
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
        """Mark a single notification as read."""
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
        """Mark all notifications for the authenticated user as read."""
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
            