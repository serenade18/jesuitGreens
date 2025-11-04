from django.contrib.auth.hashers import make_password
from django.shortcuts import render, get_object_or_404
from rest_framework import viewsets, status
from rest_framework.exceptions import ValidationError, PermissionDenied
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from greenApp.models import UserAccount
from greenApp.permissions import IsAdminRole
from greenApp.serializers import UserAccountSerializer, UserCreateSerializer


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
        if request.user.user_type != "admin" and request.user.pk != user.pk:
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
        if request.user.user_type != "admin" and request.user.pk != user.pk:
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
        if request.user.user_type != "admin" and request.user.pk != user.pk:
            raise PermissionDenied("You can only delete your own account.")

        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
